
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import java.util.Properties;


public class ServerJetty {

    public static void main(String[] args) throws Exception {

        final Server server;
        // 读取配置文件

        Properties konaSslProperties = KonaSslPropertiesUtil.getKonaSslProperties();


        server = new Server();

        String keystorePath = konaSslProperties.getProperty("keystorePath");
        String keystorePassword = konaSslProperties.getProperty("keystorePassword");
        String truststorePath = konaSslProperties.getProperty("truststorePath");

        //从trustStore，keyStore库文件load
        KeyStore keyStore = KonaSslContextUtil.getKeyStore(Files.newInputStream(Paths.get(keystorePath)), keystorePassword.toCharArray());

//        KeyStore trustStore = KonaSslContextUtil.getTrustStore(Files.newInputStream(Paths.get(truststorePath)), "comstar".toCharArray());
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        //传入相应指定的文件,单向认证，服务端一般只要keyStore文件
        sslContextFactory.setSslContext(KonaSslContextUtil.getJavaSSLContext(null, keyStore, keystorePassword.toCharArray()));
        HttpConfiguration configuration = new HttpConfiguration();
        configuration.setSecureScheme("https");
        configuration.addCustomizer(new SecureRequestCustomizer());

        ServerConnector sslServerConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(configuration));
        sslServerConnector.setPort(9004);
        server.addConnector(sslServerConnector);
        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        context.addServlet(HelloServlet.class, "/hello");
        server.setHandler(new HandlerList(context, new DefaultHandler()));


        try {
            //启动
            server.start();
            server.dumpStdErr();
            //卡住主线程，开始监听
            server.join();
        }catch (InterruptedException e){
            Thread.currentThread().interrupt();
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    public static class HelloServlet extends HttpServlet {

        private static final long serialVersionUID = -4748362333014218314L;

        @Override
        public void doGet(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("Hello!");
        }

        @Override
        public void doPost(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            doGet(request, response);
        }
    }
}
