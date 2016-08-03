package eidas.saml;

import org.junit.Test;

import eidas.saml.ProxyURIComparator;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProxyURIComparatorTest {

  private ProxyURIComparator subject = new ProxyURIComparator("https://eidas.test.surfconext.nl", "http://localhost:9290");

  @Test
  public void testCompare() throws Exception {
    assertFalse(subject.compare("https://eidas.test.surfconext.nl/saml/idp/login", null));
    assertFalse(subject.compare(null, "https://eidas.test.surfconext.nl/saml/idp/login"));

    assertTrue(subject.compare(null, null));
    assertTrue(subject.compare("https://eidas.test.surfconext.nl/saml/idp/login", "http://localhost:9290/saml/idp/login"));
    assertTrue(subject.compare("http://localhost:9290/saml/idp/login", "https://eidas.test.surfconext.nl/saml/idp/login"));
  }
}
