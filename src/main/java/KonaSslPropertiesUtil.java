
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author chengboran
 * @description
 * @date 2024/4/15 15:20
 */
public class KonaSslPropertiesUtil {
    private static final Properties konaSslProperties;
    static {
        InputStream resourceAsStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("konaSsl.properties");
        konaSslProperties = new Properties();
        try {
            konaSslProperties.load(resourceAsStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static Properties getKonaSslProperties() {
        return konaSslProperties;

    }
}
