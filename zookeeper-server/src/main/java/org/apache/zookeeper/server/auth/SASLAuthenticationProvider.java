/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server.auth;

import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.server.ServerCnxn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SASLAuthenticationProvider implements AuthenticationProvider {
    private static Logger LOG = LoggerFactory.getLogger(SASLAuthenticationProvider.class);

    public String getScheme() {
        LOG.error("=== run in getSchema");
        return "sasl";
    }

    public KeeperException.Code handleAuthentication(ServerCnxn cnxn, byte[] authData) {
        // Should never call this: SASL authentication is negotiated at session initiation.
        // TODO: consider substituting current implementation of direct ClientCnxn manipulation with
        // a call to this method (SASLAuthenticationProvider:handleAuthentication()) at session initiation.
        LOG.error("=== run in handleAuthentication, ServerCnxn: " + cnxn.getAuthInfo().size() + ", authData: " + new String(authData));
        LOG.error("=== run in handleAuthentication, ServerCnxn: " + cnxn.getAuthInfo().get(0).getScheme() + ", " + cnxn.getAuthInfo().get(0).getId() + ", authData: " + new String(authData));
        return KeeperException.Code.AUTHFAILED;

    }

    public boolean matches(String id, String aclExpr) {
        LOG.error("=== run in matches, id: " + id + ", aclExpr: " + aclExpr);
        if ((id.equals("super") || id.equals(aclExpr))) {
            return true;
        }
        String readAccessUser = System.getProperty("zookeeper.letAnySaslUserDoX");
        return readAccessUser != null && aclExpr.equals(readAccessUser);
    }

    public boolean isAuthenticated() {
        LOG.error("==== run in isAuthenticated");
        return true;
    }

    public boolean isValid(String id) {
        LOG.error("==== run in isValid, id: " + id);
        // Since the SASL authenticator will usually be used with Kerberos authentication,
        // it should enforce that these names are valid according to Kerberos's
        // syntax for principals.
        //
        // Use the KerberosName(id) constructor to define validity:
        // if KerberosName(id) throws IllegalArgumentException, then id is invalid.
        // otherwise, it is valid.
        //
        try {
            KerberosName kn = new KerberosName(id);
            LOG.error("=== in isValid, " + kn.getHostName() + " " + kn.toString());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

}
