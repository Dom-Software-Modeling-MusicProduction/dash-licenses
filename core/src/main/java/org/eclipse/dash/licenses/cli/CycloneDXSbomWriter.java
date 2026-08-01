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
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.LicenseData;
import org.eclipse.dash.licenses.PackageUrlIdParser;

public class CycloneDXSbomWriter implements IResultsCollector {

	private static final PackageUrlIdParser PACKAGE_URL_ID_PARSER = new PackageUrlIdParser();
	
	private Map<IContentId, LicenseData> licenceMap = new HashMap<>();
	private File output;
	private Bom sbom;
	
	public CycloneDXSbomWriter(Bom sbom, File output) {
		this.sbom = sbom;
		this.output = output;
	}

	@Override
	public void accept(LicenseData data) {
		licenceMap.put(data.getId(), data);
	}

	@Override
	public void close() {
        if (sbom.getComponents() != null) {
            for (Component component : sbom.getComponents()) {
                String purl = component.getPurl();
                if (purl == null) continue;

                var id = PACKAGE_URL_ID_PARSER.parseId(purl);
                if (id != null) {
                	var data = licenceMap.get(id);
                	if (data == null) continue;
                	
                	if (data.getLicense() != null) {
                		License license = new License();
                		license.setId(data.getLicense());
                		LicenseChoice licenseChoice = new LicenseChoice();
                		licenseChoice.addLicense(license);
                		component.setLicenses(licenseChoice);
                	}
                }
           }
        }
		
        String json = BomGeneratorFactory.createJson(Version.VERSION_14, sbom).toJsonString();
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json);
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
