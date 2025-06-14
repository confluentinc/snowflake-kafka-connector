package com.snowflake.kafka.connector;

import com.snowflake.kafka.connector.internal.InternalUtils;
import net.snowflake.client.core.SFSessionProperty;
import org.junit.Test;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class SnowflakeProxyConfigTest {

    @Test
    public void testSnowflakeProxyConfigValidation() {
        Map<String, String> config = new HashMap<>();
        
        // Test valid config with host and port
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_USE_HTTPS_PROXY, "true");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT, "8080");
        
        Properties proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertTrue(proxyProps.containsKey(SFSessionProperty.USE_PROXY.getPropertyKey()));
        assertEquals("true", proxyProps.getProperty(SFSessionProperty.USE_PROXY.getPropertyKey()));
        assertEquals("proxy.example.com", proxyProps.getProperty(SFSessionProperty.PROXY_HOST.getPropertyKey()));
        assertEquals("8080", proxyProps.getProperty(SFSessionProperty.PROXY_PORT.getPropertyKey()));
        
        // Test missing host
        config.remove(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST);
        proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertFalse(proxyProps.containsKey(SFSessionProperty.USE_PROXY.getPropertyKey()));
        
        // Test missing port
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.remove(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT);
        proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertFalse(proxyProps.containsKey(SFSessionProperty.USE_PROXY.getPropertyKey()));
    }

    @Test
    public void testSnowflakeProxyWithAuth() {
        Map<String, String> config = new HashMap<>();
        
        // Test with auth credentials
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_USE_HTTPS_PROXY, "true");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT, "8080");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_USER, "proxyuser");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PASSWORD, "proxypass");
        
        Properties proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertTrue(proxyProps.containsKey(SFSessionProperty.PROXY_USER.getPropertyKey()));
        assertTrue(proxyProps.containsKey(SFSessionProperty.PROXY_PASSWORD.getPropertyKey()));
        assertEquals("proxyuser", proxyProps.getProperty(SFSessionProperty.PROXY_USER.getPropertyKey()));
        assertEquals("proxypass", proxyProps.getProperty(SFSessionProperty.PROXY_PASSWORD.getPropertyKey()));
        
        // Test missing password
        config.remove(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PASSWORD);
        proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertFalse(proxyProps.containsKey(SFSessionProperty.PROXY_USER.getPropertyKey()));
        assertFalse(proxyProps.containsKey(SFSessionProperty.PROXY_PASSWORD.getPropertyKey()));
    }

    @Test
    public void testSnowflakeProxyNonProxyHosts() {
        Map<String, String> config = new HashMap<>();
        
        // Test with non-proxy hosts
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_USE_HTTPS_PROXY, "true");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT, "8080");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_NON_PROXY_HOSTS, "localhost,127.0.0.1");
        
        Properties proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        assertTrue(proxyProps.containsKey(SFSessionProperty.NON_PROXY_HOSTS.getPropertyKey()));
        assertEquals("localhost,127.0.0.1", proxyProps.getProperty(SFSessionProperty.NON_PROXY_HOSTS.getPropertyKey()));
    }

    @Test
    public void testSnowflakeProxyPropertyGeneration() {
        Map<String, String> config = new HashMap<>();
        
        // Test complete proxy configuration
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_USE_HTTPS_PROXY, "true");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT, "8080");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_USER, "proxyuser");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PASSWORD, "proxypass");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_NON_PROXY_HOSTS, "localhost,127.0.0.1");
        
        Properties proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        
        // Verify all properties are set correctly
        assertEquals("true", proxyProps.getProperty(SFSessionProperty.USE_PROXY.getPropertyKey()));
        assertEquals("proxy.example.com", proxyProps.getProperty(SFSessionProperty.PROXY_HOST.getPropertyKey()));
        assertEquals("8080", proxyProps.getProperty(SFSessionProperty.PROXY_PORT.getPropertyKey()));
        assertEquals("proxyuser", proxyProps.getProperty(SFSessionProperty.PROXY_USER.getPropertyKey()));
        assertEquals("proxypass", proxyProps.getProperty(SFSessionProperty.PROXY_PASSWORD.getPropertyKey()));
        assertEquals("localhost,127.0.0.1", proxyProps.getProperty(SFSessionProperty.NON_PROXY_HOSTS.getPropertyKey()));
    }

    @Test
    public void testSnowflakeProxyPropertyGenerationWithoutAuth() {
        Map<String, String> config = new HashMap<>();
        
        // Test proxy configuration without auth
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_USE_HTTPS_PROXY, "true");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_HOST, "proxy.example.com");
        config.put(SnowflakeSinkConnectorConfig.SNOWFLAKE_HTTPS_PROXY_PORT, "8080");
        
        Properties proxyProps = InternalUtils.generateProxyParametersIfRequired(config);
        
        // Verify only non-auth properties are set
        assertEquals("true", proxyProps.getProperty(SFSessionProperty.USE_PROXY.getPropertyKey()));
        assertEquals("proxy.example.com", proxyProps.getProperty(SFSessionProperty.PROXY_HOST.getPropertyKey()));
        assertEquals("8080", proxyProps.getProperty(SFSessionProperty.PROXY_PORT.getPropertyKey()));
        assertFalse(proxyProps.containsKey(SFSessionProperty.PROXY_USER.getPropertyKey()));
        assertFalse(proxyProps.containsKey(SFSessionProperty.PROXY_PASSWORD.getPropertyKey()));
    }
} 
