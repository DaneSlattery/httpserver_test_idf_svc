// edge stack approach
use std::thread::Scope;

// use edge_executor::LocalExecutor;
use edge_http::io::server::{Connection, DefaultServer, TaskHandler};
use edge_http::Method;
use embedded_io_async::{Read, Write};
use embedded_nal_async_xtra::TcpListen;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::EspError;
use esp_idf_svc::timer::EspTaskTimerService;
use esp_idf_svc::wifi::{AsyncWifi, Configuration};
use esp_idf_svc::wifi::{ClientConfiguration, EspWifi};
use futures_lite::future::block_on;
use log::info;

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");
// ws

const INDEX_HTML: &str = include_str!("../static/index.html");

// const

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71

    esp_idf_svc::timer::embassy_time_driver::link();
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    esp_idf_svc::io::vfs::initialize_eventfd(5)?;

    std::thread::scope(|scope: &Scope| run(scope))?;

    Ok(())
}

fn run<'s>(scope: &'s Scope<'s, '_>) -> Result<(), anyhow::Error> {
    let sys_loop = EspSystemEventLoop::take().unwrap();

    let peripherals = Peripherals::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();
    let timer_service = EspTaskTimerService::new()?;
    let mut wifi = AsyncWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
        timer_service,
    )?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        password: PASSWORD.try_into().unwrap(),
        ..Default::default()
    }))?;
    block_on(connect_wifi(&mut wifi))?;
    let task: std::thread::ScopedJoinHandle<Result<(), anyhow::Error>> =
        std::thread::Builder::new()
            .stack_size(80000)
            .spawn_scoped(scope, move || {
                // let executor = LocalExecutor::<8>::new();

                // executor.spawn(connect_wifi(&mut wifi)).detach();

                let mut httpd = httpd().unwrap();

                let handler = http_handler().unwrap();

                // executor.spawn(run_ws(&mut httpd, handler)).detach();
                match block_on(run_ws(&mut httpd, handler)) {
                    Ok(_) => log::error!("Finished webserver,"),
                    Err(x) => log::error!("Error in web server, msg = {}", x),
                }
                // esp_idf_svc::hal::task::block_on());

                Ok(())
            })
            .unwrap();

    let result: Result<(), _> = task.join().unwrap();

    log::info!("Thread execution finised {result:?}");

    Ok(())
}

pub async fn run_ws<H>(server: &mut DefaultServer, handler: H) -> Result<(), anyhow::Error>
where
    H: for<'b> edge_http::io::server::TaskHandler<
        'b,
        &'b mut edge_std_nal_async::StdTcpConnection,
        64,
    >,
{
    let addr = "0.0.0.0:80";

    info!("Running HTTP ws server on {addr}");

    let acceptor = edge_std_nal_async::Stack::new()
        .listen(addr.parse().unwrap())
        .await?;
    server.run_with_task_id(acceptor, handler, None).await?;
    // server.run(acceptor, handler, None).await?;

    Ok(())
}

struct HttpHandler;

impl<'b, T, const N: usize> TaskHandler<'b, T, N> for HttpHandler
where
    T: Read + Write,
    T::Error: Send + Sync + std::error::Error + 'static,
{
    type Error = anyhow::Error;

    async fn handle(
        &self,
        task_id: usize,
        conn: &mut Connection<'b, T, N>,
    ) -> Result<(), Self::Error> {
        let headers = conn.headers()?;
        log::info!("Headers in request: {:?}", headers.headers);
        if !matches!(headers.method, Some(Method::Get)) {
            conn.initiate_response(405, Some("Method Not Allowed"), &[])
                .await?;
        } else if !matches!(headers.path, Some("/")) {
            conn.initiate_response(404, Some("Not Found"), &[]).await?;
        } else {
            conn.initiate_response(
                200,
                Some("OK"),
                &[
                    ("Content-Type", "text/html"),
                    ("Set-Cookie", "token=asd8234nsdfp982"),
                ],
            )
            .await?;
            log::info!("Task Id: {}", task_id);

            conn.write_all(INDEX_HTML.as_bytes()).await?;
        }

        Ok(())
    }
}

async fn connect_wifi(wifi: &mut AsyncWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        password: PASSWORD.try_into().unwrap(),
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start().await?;
    info!("Wifi started");

    wifi.connect().await?;
    info!("Wifi connected");

    wifi.wait_netif_up().await?;
    info!("Wifi netif up");

    Ok(())
}

fn httpd() -> Result<DefaultServer, EspError> {
    Ok(DefaultServer::new())
}

fn http_handler() -> Result<HttpHandler, EspError> {
    Ok(HttpHandler)
}
