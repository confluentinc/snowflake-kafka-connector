package com.snowflake.kafka.connector;

import net.snowflake.client.jdbc.SnowflakeDriver;
import net.snowflake.client.jdbc.internal.apache.commons.codec.binary.Base64;
import net.snowflake.client.jdbc.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SnowflakeTest {
    static final String JDBC_DATABASE = "db";
    static final String JDBC_SCHEMA = "schema";
    static final String JDBC_USER = "user";
    static final String JDBC_PRIVATE_KEY = "privateKey";
    static final String JDBC_SSL = "ssl";
    static final String JDBC_SESSION_KEEP_ALIVE = "client_session_keep_alive";
    static final String JDBC_WAREHOUSE = "warehouse"; // for test only
    static final String JDBC_NETWORK_TIMEOUT = "networkTimeout";
    private static String jdbcUrl;
    private static String sfPrivateKey = "snowflake-private-key-for-testing-put-here";
    public static void main(String[] args) {
        String connUrl = "https://CONFLUENTPARTNER1-confluent_partner.snowflakecomputing.com:443";
        Properties props = new Properties();
        Connection conn;
        fillProps(props);
        makeJdbcUrl(connUrl);
        {
            try {
                conn = new SnowflakeDriver().connect(jdbcUrl, props);
                System.out.println(conn.getCatalog());
            } catch (SQLException e) {
                System.out.println(e);
                System.out.println(e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }

    private static void makeJdbcUrl(String urlStr){
        Pattern pattern =
                Pattern.compile("^(https?://)?((([\\w\\d-]+)(\\" + ".[\\w\\d-]+){2,})(:(\\d+))?)/?$");

        Matcher matcher = pattern.matcher(urlStr.trim().toLowerCase());

        if (!matcher.find()) {
            System.out.println("Matcher couldn't find");
        }

        boolean ssl = !"http://".equals(matcher.group(1));

        String url = matcher.group(3);

        String account = matcher.group(4);
        int port;
        if (matcher.group(7) != null) {
            port = Integer.parseInt(matcher.group(7));
        } else if (ssl) {
            port = 443;
        } else {
            port = 80;
        }

        jdbcUrl = "jdbc:snowflake://" + url + ":" + port;
    }

    private static void fillProps(Properties properties){
        properties.put(JDBC_DATABASE, "TEST_DB");
        properties.put(JDBC_PRIVATE_KEY, parsePrivateKey(sfPrivateKey));
        properties.put(JDBC_SCHEMA, "PUBLIC");
        properties.put(JDBC_USER, "connectsystemtest");
        properties.put("warehouse", "DEMO_WH");
    }

    static PrivateKey parsePrivateKey(String key) {
        // remove header, footer, and line breaks
        key = key.replaceAll("-+[A-Za-z ]+-+", "");
        key = key.replaceAll("\\s", "");

        java.security.Security.addProvider(new BouncyCastleProvider());
        byte[] encoded = Base64.decodeBase64(key);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            System.out.println("Exception while parsing private key");
            throw new RuntimeException("key parsing failure");
        }
    }
}