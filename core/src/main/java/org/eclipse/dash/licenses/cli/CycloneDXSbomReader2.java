/*************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution, and is available at https://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *************************************************************************/
package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;

public class CycloneDXSbomReader2 implements IDependencyListReader { 

	private Bom sbom;

    private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

    private CycloneDXSbomReader2(Bom bom) {
		sbom = bom;
	}

    /**
     * Create a reader for the file if possible. Return <code>null</code> otherwise.
     * 
     * @param file
     * @return an instance of {@link CycloneDXSbomReader} or <code>null</code>.
     */
	public static CycloneDXSbomReader2 forFile(File file) {
    	if (file.getName().endsWith(".json")) {
    		try {
				return new CycloneDXSbomReader2(new JsonParser().parse(file));
			} catch (ParseException e) {
				return null;
			}
    	}    	
    	if (file.getName().endsWith(".xml")) {
    		try {
				return new CycloneDXSbomReader2(new XmlParser().parse(file));
			} catch (ParseException e) {
				return null;
			}
    	}
    	return null;
    }

    @Override
    public Collection<IContentId> getContentIds() {
        List<IContentId> results = new ArrayList<>();
        if (sbom.getMetadata() != null && sbom.getMetadata().getComponent() != null) {
            IContentId id = PURL_PARSER.parseId(sbom.getMetadata().getComponent().getPurl());
            if (id != null) {
                results.add(id);
            }
        }
        if (sbom.getComponents() != null) {
            for (var component : sbom.getComponents()) {
                IContentId id = PURL_PARSER.parseId(component.getPurl());
                if (id != null) {
                    results.add(id);
                }
            }
        }
        return results;
    }

	public Bom getSbom() {
		return sbom;
	}
}
