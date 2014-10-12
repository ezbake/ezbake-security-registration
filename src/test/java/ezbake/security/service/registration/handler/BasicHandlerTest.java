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

import ezbake.security.thrift.RegistrationException;
import ezbake.security.thrift.SecurityIDNotFoundException;
import org.apache.thrift.TException;
import org.junit.*;

/**
 * User: jhastings
 * Date: 4/8/14
 * Time: 11:41 AM
 */
public class BasicHandlerTest extends HandlerBaseTest {



    private static final String cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIICoDCCAYigAwIBAgIBBDANBgkqhkiG9w0BAQUFADATMREwDwYDVQQDEwhlemJh\n" +
            "a2VjYTAgFw0xNDA1MjcxNDAzMDRaGA8yMDE3MDUyNzE0MDMwNFowEjEQMA4GA1UE\n" +
            "AxQHX0V6X1JlZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALYQL8xy\n" +
            "QcY7G5rdDxLVjIdcF58+fM3ywN5MKy/RigIH02YoFj7MqWeKy33C0HB0s5f8j/dI\n" +
            "+XYi5Jktns+sFm5ZaFpIGemzRS3TBty8lZ675/45GdQto5ZThmLRtEnEu3aP+szP\n" +
            "MkRWFQpxNEspnqZ3Ykm0LN+9uDUrfCGk1h4kLBEIVSMWbSxHaUsYlCtEYvhHqeMU\n" +
            "+4aA3ubO3GzW1u9GG5d5Ka2ZNcrNEPI55k+LsiuZpel2XyynKN6UB3KaGWwZ3wT9\n" +
            "5VTFCYqkZtm+MM2hiqGppr58M+EMcEBKWS2ycK9w2VO2holtVEJMuQnl63+OTdc/\n" +
            "MoS2SuqI1d75hisCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAHyIjHljiPRvAV7Aq\n" +
            "+53sC8LN9ylsi/YgLFLw8H6ZcopcPpdYSr3j1GseZqksv/XEjrfJPprpNgG2f7b7\n" +
            "B7vkdGs3cTMlOUEFiOyyLG4dXIARYWDEALQABkZYCq7H6JKZlN1aplcAqYmgU6+x\n" +
            "KDWGIQO3CUkRS0egfK3oQ2oc8XnzxSLqnvX8hRHRtEEMdoyNKuPy04j2WcUgO85e\n" +
            "aVqDBbrJD5XcOEFAgBnWfexlX4guu3WQH6KI8F3S+hOCi1a8pkkuHu9q5KJODiEF\n" +
            "nr8xQgj1TsPSbTnlDYgrlHBWdT+HvB9I2Ms08ue1T7JDMzcwwSqAVOu2YTTXaK0H\n" +
            "h/uQeA==\n" +
            "-----END CERTIFICATE-----";

    private static final String pk = //"-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2EC/MckHGOxua\n" +
            "3Q8S1YyHXBefPnzN8sDeTCsv0YoCB9NmKBY+zKlnist9wtBwdLOX/I/3SPl2IuSZ\n" +
            "LZ7PrBZuWWhaSBnps0Ut0wbcvJWeu+f+ORnULaOWU4Zi0bRJxLt2j/rMzzJEVhUK\n" +
            "cTRLKZ6md2JJtCzfvbg1K3whpNYeJCwRCFUjFm0sR2lLGJQrRGL4R6njFPuGgN7m\n" +
            "ztxs1tbvRhuXeSmtmTXKzRDyOeZPi7IrmaXpdl8spyjelAdymhlsGd8E/eVUxQmK\n" +
            "pGbZvjDNoYqhqaa+fDPhDHBASlktsnCvcNlTtoaJbVRCTLkJ5et/jk3XPzKEtkrq\n" +
            "iNXe+YYrAgMBAAECggEAekZOw+FsuWTTOmQDDqQrmHFKUCIYkfzaebHwQ1JYfNqi\n" +
            "qPZ9UjoEAE1gM5tWgGBwicAPNIZnPGdc3l+cTF+IRR55DkFkXeePq6IR9sgVOKF8\n" +
            "wum4ph7swjZgiBfNHMorGQrD5y+00954jSXQeDaAnc6KTXPbu3zgrZ0B5lqdj2mb\n" +
            "wIVpgmYPOVR6Y9c0jOzvKW31qAxjm2tX3qkGH5pYbb0Bqe7SNMMIBRx0oY9i0no8\n" +
            "84+24lvENIVtXMaZV1Ndb8XbYwwiZbvcN9V6R9irKOUGhJScq5Z/wzFyFJMe7xeY\n" +
            "BXiXG4AQ6GQ5QsGVbcemM5Q5t41ZOCUgToCkuY95SQKBgQDb/YD4om8Muar30bsR\n" +
            "9ulkNewX3nUDCMITaDpVbAUh9vCbapSyn1KnC4lvowq9LvKPjRBbebfpJTV90JIt\n" +
            "W5Wt+RcYe/Vxzh/w3DSV4hdPk2au1HoY26LEQBgq8t1EOO4pYEoKi5S9oVmGrl7y\n" +
            "U0JgGctqvNtsgzHErO/HGiV0xQKBgQDT3WKCfT9+7ZoovB7BX50Pk9nFD5yGDv/U\n" +
            "eAUnS0OHnWan+FuS/k8LchMbaJ/KBA1LOqmXYmdWQOYIlvMqUycUcCjBHvc9EdSz\n" +
            "yKP5rE8i9vVsI3rd4wRdBkVqrtufH9+RR3t3CEEqqCCitmt2lOAXXO4Hq7r4o44S\n" +
            "a0Lav2IeLwKBgCd3EeUI1t00jbxJjsLJRdNpbQJXMSyrLI3ou9ZJO559O2rWMvjc\n" +
            "Zip7gltZp3qK6o7gIpgWfOzBdRguC5tBe9erAP6udjjFXquKBZEB72aiLeCdU44U\n" +
            "EN4eFXfW++TaRbd8g6vioHtob7Qeof/c+eJdnkV2vfJ4krwSvi08vo11AoGBAMaS\n" +
            "W88z9vxPVErTrvvNUtcT22sgq7LWgh+w8huXJk8ITvwmAiZupsVygMgSsplUXOVi\n" +
            "sStLNtGX+EKawISt9RXp3bjL/izF9pce+dl8D5wU3YgiZPls2l0aEJviEcQ9ynxP\n" +
            "BEBXg0So2hXHZkd5V+Nt3UdhRNff67wFvl5qPFtPAoGBANlmhWPG4HyFbOZ/CAiL\n" +
            "puVCnAaS4VqY/v67nNINzVyRUgOD8EgYvo310eTbd7xTpxYW7mLEubK4gBi4iznX\n" +
            "OPCdjW1/9sUaZyGuxvBCF3GOwudLIt9uqtINZGtEYEvMx8ZFYHPjRfj9+fH5nRZ3\n" +
            "cRlu+DsX9n2LUiEm1kzsnCoT";
            //"-----END PRIVATE KEY-----";




    @Test
    public void testGenerateIdNotNegative() {
        for (int i=0; i < 1000; ++i) {
            String id = handler.generateSecurtyId();
            long idL = Long.parseLong(id);
            Assert.assertTrue(idL >= 0);
        }
    }

    @Test
    public void testPing() throws TException {
        Assert.assertTrue(handler.ping());
    }

    @Test(expected=SecurityIDNotFoundException.class)
    public void testStatusNoRegistration() throws RegistrationException, SecurityIDNotFoundException, TException {
        handler.getStatus(getTestEzSecurityToken(false), "DoesNotExist");
    }

}
