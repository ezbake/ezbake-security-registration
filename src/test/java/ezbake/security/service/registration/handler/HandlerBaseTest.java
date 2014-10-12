/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

package ezbake.security.service.registration.handler;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import ezbake.base.thrift.*;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.crypto.PKeyCryptoException;
import ezbake.local.zookeeper.LocalZookeeper;
import ezbake.security.common.core.EzSecurityConstant;
import ezbake.security.common.core.SecurityID;
import ezbake.security.persistence.impl.AccumuloRegistrationManager;
import ezbake.security.persistence.model.AppPersistCryptoException;
import ezbake.security.persistence.model.AppPersistenceModel;
import ezbake.security.test.MockEzSecurityToken;
import ezbakehelpers.accumulo.AccumuloHelper;

import org.apache.accumulo.core.client.*;
import org.junit.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

/**
 * User: jhastings
 * Date: 4/8/14
 * Time: 1:20 PM
 */
public class HandlerBaseTest {

    private static Logger log = LoggerFactory.getLogger(BasicHandlerTest.class);
    public static final String TEST_TABLE_NAME = "register";

    public static final String ca = "-----BEGIN CERTIFICATE-----\n" +
            "MIIC6DCCAdCgAwIBAgIBATANBgkqhkiG9w0BAQUFADATMREwDwYDVQQDEwhlemJh\n" +
            "a2VjYTAgFw0xNDA1MjcxMzUxNTNaGA8yMDI0MDUyNzEzNTE1M1owEzERMA8GA1UE\n" +
            "AxMIZXpiYWtlY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy8CxQ\n" +
            "xLacvDy0cwdcc0N975hfufCMjIAzeW9LHgjhZ9CfBZtLD6pV9bWq36wI8FJg2ftN\n" +
            "/Tg9MSwdm/aAAFLsKrpEVVptk5Mha9U1H1x+uxjOn4c3lat1397udLUo9U0qR62H\n" +
            "X1/AQD5OPhkFSS6BgyhLVqTEMJ7SjGg7SNAo5EyKNVqTGlNamaEMuOfnkyCiyMUX\n" +
            "5Up6/h8f6WuOcXEGviUnA6K9luNpfBcSiGasvHrfj1Z1/XK1fzX4+SPizcvK0qyN\n" +
            "Deb/XjEZFgnFXH0XxjFyvV4EGiP2FbwVTpz416IJHLZTOOc6oeAnr8IZYo9a4jpc\n" +
            "a+OFj88INx+P3nAlAgMBAAGjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0P\n" +
            "AQH/BAQDAgEGMB0GA1UdDgQWBBRMMyuLxZz/dywUAPVmXyFutscf0TANBgkqhkiG\n" +
            "9w0BAQUFAAOCAQEAKOzB4lXg6Yj5HrBghOgzFPjJ3/UbySMunSN+IrKhj+6dnbek\n" +
            "m7rNSnKrsheAcewmz5h95ZhHJ3YelOg6dVfhLlZT4Q4eVu3tpmh9IEFfMXm/1DiW\n" +
            "Gx00+FmvTEwbTqAV0RUp0AWURczJsuEg+E2TTnhy7yAVbpJvMAkW1RQwiJVavvxZ\n" +
            "DG/9WA6JajGQDWeXx2t4maRwxMbMjEVFjF12jXMgJsjvxLgIl7f9zISSUvN0CCqr\n" +
            "dHFrEHVGzIAVs6bDZvY11SJX0VejuUcCaHK1/s1dT1JjOaqjGxpHFtE77awhifIO\n" +
            "/fCk16VfKrLfd1jLWrr+UMeK+/ZJPEpE9Nyv5A==\n" +
            "-----END CERTIFICATE-----";

    protected static Properties ezConfig;
    private static LocalZookeeper localZookeeper;
    private static int zooPort = 2188;

    protected EzSecurityRegistrationHandler handler;

    @BeforeClass
    public static void setUpClass() throws Exception {
        ezConfig = new EzConfiguration(new ClasspathConfigurationLoader()).getProperties();


        // Set up a zookeeper for the client pool
        localZookeeper = new LocalZookeeper(zooPort);
        ezConfig.setProperty(EzBakePropertyConstants.ZOOKEEPER_CONNECTION_STRING, localZookeeper.getConnectionString());
    }

    @AfterClass
    public static void tearDownClass() throws IOException {
        if (localZookeeper != null) {
            localZookeeper.shutdown();
        }
    }

    @Before
    public void setUpTest() throws AccumuloSecurityException, AccumuloException, IOException, TableNotFoundException, AppPersistCryptoException, PKeyCryptoException {
        Connector conn = new AccumuloHelper(ezConfig).getConnector();
        try {
            conn.tableOperations().delete(AccumuloRegistrationManager.REG_TABLE);
            conn.tableOperations().delete(AccumuloRegistrationManager.LOOKUP_TABLE);
        } catch (TableNotFoundException e) {
            // ignore
        }
        handler = new EzSecurityRegistrationHandler(ezConfig);

        BatchWriter writer = conn.createBatchWriter(AccumuloRegistrationManager.REG_TABLE,1000000L, 1000L, 10);
        AppPersistenceModel m = new AppPersistenceModel();
        m.setId(SecurityID.ReservedSecurityId.CA.getId());
        m.setX509Cert(ca);
        writer.addMutations(m.getObjectMutations());

        AppPersistenceModel n = new AppPersistenceModel();
        m.setId(SecurityID.ReservedSecurityId.EzSecurity.getId());
        m.setPublicKey("PublicKey");
        writer.addMutations(m.getObjectMutations());

        writer.close();
    }



    public EzSecurityToken getTestEzSecurityToken() {
        return getTestEzSecurityToken(false);
    }

    public EzSecurityToken getTestEzSecurityToken(boolean admin) {
        return getTestEzSecurityToken(admin, "dn");
    }

    public EzSecurityToken getTestEzSecurityToken(boolean admin, String dn) {
        EzSecurityToken token = MockEzSecurityToken.getBlankToken("SecurityClientTest", null, System.currentTimeMillis()+1000);
        MockEzSecurityToken.populateExternalProjectGroups(token, Maps.<String, List<String>>newHashMap(), admin);
        MockEzSecurityToken.populateAuthorizations(token, "high", Sets.newHashSet("U"));
        MockEzSecurityToken.populateUserInfo(token, dn, "USA", null);
        return token;
    }
}
