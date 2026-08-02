package org.eclipse.dash.licenses.tests.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Collection;

import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.cli.CycloneDXSbomReader;
import org.eclipse.dash.licenses.cli.IDependencyListReader;
import org.eclipse.dash.licenses.cli.SpdxSbomReader;
import org.junit.jupiter.api.Test;

class SbomFileReaderRdfTest {

    // The reader chain Main uses: try CycloneDX, then SPDX.
    private static IDependencyListReader readerFor(File file) {
        IDependencyListReader reader = CycloneDXSbomReader.forFile(file);
        if (reader == null) {
            reader = SpdxSbomReader.forFile(file);
        }
        return reader;
    }

    @Test
    void testParseSpdxRdfXml() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("test.spdx.rdf").getFile());
        IDependencyListReader reader = readerFor(file);

        Collection<IContentId> ids = reader.getContentIds();

        assertNotNull(ids);
        assertFalse(ids.isEmpty(), "Expected at least one content ID");

        IContentId id = ids.iterator().next();
        assertEquals("maven", id.getType());
        assertEquals("org.apache.commons", id.getNamespace());
        assertEquals("commons-lang3", id.getName());
        assertEquals("3.12.0", id.getVersion());
    }

    @Test
    void testParseSpdxRdfXml_skipsNonPurl() throws Exception {
        // Verifies that non-purl externalRefs are ignored
        File file = new File(getClass().getClassLoader().getResource("test.spdx.rdf").getFile());
        IDependencyListReader reader = readerFor(file);

        Collection<IContentId> ids = reader.getContentIds();

        // Only the purl ref should be returned, not any other ref types
        assertEquals(1, ids.size());
    }
}
