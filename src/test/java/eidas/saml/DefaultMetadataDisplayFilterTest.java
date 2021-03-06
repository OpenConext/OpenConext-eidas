package eidas.saml;

import eidas.AbstractIntegrationTest;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class DefaultMetadataDisplayFilterTest extends AbstractIntegrationTest{

  @Test
  public void testProcessMetadataDisplay() throws Exception {
    String metadata = restTemplate.getForObject("http://localhost:" + port + "/sp/metadata", String.class);
    assertTrue(metadata.contains("entityID=\"https://eidas.localhost.surfconext.nl\""));
  }
}
