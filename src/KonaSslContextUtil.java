import com.tencent.kona.KonaProvider;
//import org.eclipse.jetty.client.HttpClient;
//import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public final class KonaSslContextUtil {

    static {
        try {
            Provider provider = new KonaProvider();
            Security.insertProviderAt(provider, 1);
        } catch (Throwable ex) {
        }
    }

    public static void demo() throws Exception {

        String password = "";

        //从trustStore，keyStore库文件load
        Properties konaSslProperties = KonaSslPropertiesUtil.getKonaSslProperties();

        String keystorePath = konaSslProperties.getProperty("keystorePath");
        String truststorePath = konaSslProperties.getProperty("truststorePath");


        String keystorePassword = konaSslProperties.getProperty("keystorePassword");
        KeyStore keyStore = getKeyStore(Files.newInputStream(Paths.get(keystorePath)), keystorePassword.toCharArray());
        KeyStore trustStore = getTrustStore(Files.newInputStream(Paths.get(truststorePath)), keystorePassword.toCharArray());

        //创建java SSLContext
        SSLContext javaSSLContext = getJavaSSLContext(trustStore, keyStore, keystorePassword.toCharArray());


        //javaSslSocket
        SSLSocket sslSocket = getJavaSSLSocket(javaSSLContext);
        sslSocket.connect(new InetSocketAddress("127.0.0.1", 9004), 2000);
        sslSocket.startHandshake();

    }

    public static void main(String[] args) throws Exception {
        HttpClient client = createClient();
        client.start();

        // Access Servlet /hello over HTTPS scheme.
        ContentResponse response = client.GET(
                new URI(String.format("https://127.0.0.1:%d/hello", 9004)));
        client.stop();
        System.out.println(response.getContentAsString());
//        demo();
    }

    private static HttpClient createClient() throws Exception {
        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        Properties konaSslProperties = KonaSslPropertiesUtil.getKonaSslProperties();
        String truststorePath = konaSslProperties.getProperty("truststorePath");
        String keystorePath = konaSslProperties.getProperty("keystorePath");

        KeyStore trustStore = getTrustStore(Files.newInputStream(Paths.get(truststorePath)),"comstar".toCharArray());
//        KeyStore keyStore = getKeyStore(Files.newInputStream(Paths.get(keystorePath)),"comstar".toCharArray());
        //传入相应指定的文件,单向认证，客户端一般只要trustStore文件
        sslContextFactory.setSslContext(getJavaSSLContext(trustStore, null, null));

        return new HttpClient(sslContextFactory);
    }



    public static SSLSocket getJavaSSLSocket(SSLContext javaSslContext) throws Exception {
        SocketFactory socketFactory = javaSslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket();
        //"TLCP_ECC_SM4_CBC_SM3","ECC_SM4_CBC_SM3"
        sslSocket.setEnabledCipherSuites(new String[]{"TLCP_ECC_SM4_CBC_SM3"});
        sslSocket.setUseClientMode(true);
        sslSocket.setTcpNoDelay(true);
        return sslSocket;
    }

    /**
     * 从 trustStore，keyStore 创建Java SSLContext
     *
     * @param trustStore
     * @param keyStore
     * @param keyPassword
     * @return
     * @throws Exception
     */
    public static SSLContext getJavaSSLContext(KeyStore trustStore, KeyStore keyStore, char[] keyPassword) throws Exception {
        TrustManagerFactory tmf = null;
        if (trustStore != null) {
            tmf = TrustManagerFactory.getInstance("PKIX", "Kona");
            tmf.init(trustStore);
        }

        //SunX509,NewSunX509
        KeyManagerFactory kmf = null;
        if (keyStore != null) {
            kmf = KeyManagerFactory.getInstance("SunX509", "Kona");
            kmf.init(keyStore, keyPassword);
        }

        SSLContext context = SSLContext.getInstance("TLCP", "Kona");
        context.init(kmf == null ? null : kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    public static KeyStore getTrustStore(InputStream stream, char[] password) throws Exception {
        //"PKCS12", "JKS"
        return getKeyStore(stream, password);
    }

    public static KeyStore getKeyStore(InputStream stream, char[] password) throws Exception {
        //"PKCS12", "JKS"
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "Kona");
        keyStore.load(stream, password);
        return keyStore;
    }


    public static KeyStore getTrustStore(String caStr) throws Exception {
        //"PKCS12", "JKS"
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "Kona");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("tlcp-trust-comstar", loadCert(caStr, null));
        return trustStore;
    }

    public static KeyStore getKeyStore(
            String signEeStr, String signEeKeyStr,
            String encEeStr, String encEeKeyStr, String password)
            throws Exception {
        //"PKCS12", "JKS"
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "Kona");
        keyStore.load(null, null);

        if (password != null) {
            keyStore.setKeyEntry("tlcp-sign-ee-comstar",
                    loadPrivateKey(signEeKeyStr),
                    password.toCharArray(),
                    new Certificate[]{loadCert(signEeStr, null)});
            keyStore.setKeyEntry("tlcp-enc-ee-comstar",
                    loadPrivateKey(encEeKeyStr),
                    password.toCharArray(),
                    new Certificate[]{loadCert(encEeStr, null)});
        } else {
            keyStore.setKeyEntry("tlcp-sign-ee-comstar",
                    loadPrivateKey(signEeKeyStr).getEncoded(),
                    new Certificate[]{loadCert(signEeStr, null)});
            keyStore.setKeyEntry("tlcp-enc-ee-comstar",
                    loadPrivateKey(encEeKeyStr).getEncoded(),
                    new Certificate[]{loadCert(encEeStr, null)});
        }

        return keyStore;
    }

    private static X509Certificate loadCert(String certPEM, String id) throws Exception {
        //"X.509"
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "Kona");
        X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes()));
        //id是国密特有的东西
//        if (id != null && !id.isEmpty()) {
//            ((SMCertificate) x509Cert).setId(id.getBytes(
//                    "UTF-8"));
//        }

        return x509Cert;
    }

    private static PrivateKey loadPrivateKey(String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        //"EC", "SM2"
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "Kona");
        return keyFactory.generatePrivate(privateKeySpec);
    }

}