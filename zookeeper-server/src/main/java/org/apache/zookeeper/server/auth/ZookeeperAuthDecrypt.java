package org.apache.zookeeper.server.auth;

import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ZooKeeperSaslServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ZookeeperAuthDecrypt extends ServerAuthenticationProvider {
    private static Logger LOG = LoggerFactory.getLogger(ZookeeperAuthDecrypt.class);

    private static final String superEncryptInfo = System.getProperty("zookeeper.FusiondirectorAuthenticationProvider.adminDigest");

    private String encryptData(String idPassword) {
        String[] parts = idPassword.split(":", 2);
        // encrypt password with append "_1"
        return parts[0] + ":" + parts[1] + "_1";

    }
    @Override
    public KeeperException.Code handleAuthentication(ServerObjs serverObjs, byte[] authData) {
        LOG.error("----- superInfo {}", superEncryptInfo);
        String idPassword = new String(authData);
        String encryptIdPassword = encryptData(idPassword);
        LOG.error("------ info {}, encrypt: {}", idPassword, encryptIdPassword);
        if (encryptIdPassword.equals(superEncryptInfo)) {
//            serverObjs.getCnxn().addAuthInfo(new Id("super", ""));
//            serverObjs.getCnxn().addAuthInfo(new Id(getScheme(), encryptIdPassword));
            return KeeperException.Code.OK;
        }
        return KeeperException.Code.AUTHFAILED;
    }

    @Override
    public boolean matches(ServerObjs serverObjs, MatchValues matchValues) {
        LOG.error("xxxxx in matches, ServerObjs: " + serverObjs.getZks().toString() + ", matchValues: " + matchValues.getAclExpr());
        LOG.error("xxxxx in matches, ServerObjs: " + serverObjs.getZks().toString() + ", matchValues: " + matchValues.getId());
        LOG.error("xxxxx in matches, ServerObjs: " + serverObjs.getZks().toString() + ", matchValues: " + matchValues.getPath());
//        return matchValues.getId().equals(matchValues.getAclExpr());
        return true;
    }

    @Override
    public String getScheme() {
        LOG.error("call get schema");
        return "sasl";
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public boolean isValid(String id) {
        LOG.error("xxxx isValid, id" + id);
        return true;
    }

    @Override
    public String getUserName(String id) {
        return id.split(":", 2)[0];
    }
}
