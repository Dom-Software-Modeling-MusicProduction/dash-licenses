package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileWriter;
//import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Component;
//import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
//import org.cyclonedx.model.Component;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.dash.licenses.LicenseData;
import org.eclipse.dash.licenses.LicenseSupport.Status;

public class SbomFileWriter implements IResultsCollector {

    private final File inputFile;
    private final File outputFile;
    private final List<LicenseData> collectedData = new ArrayList<>();

    public SbomFileWriter(File inputFile, File outputFile) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
    }

    // accumulate license data exactly like CSVCollector does
    //@Override
    public void accept(LicenseData data) {
        collectedData.add(data);
    }

    //@Override
    public void close() {
        String format = detectOutputFormat();
        System.out.println("[SbomFileWriter] Writing enriched SBOM to: " + outputFile.getPath());
        System.out.println("[SbomFileWriter] Detected format: " + format);

        switch (format) {
            case "CYCLONEDX_JSON":
                writeCycloneDxJson();
                break;
            case "CYCLONEDX_XML":
                System.out.println("[SbomFileWriter] writeCycloneDxXml: NOT YET IMPLEMENTED");
                break;
            case "CYCLONEDX_YAML":
                System.out.println("[SbomFileWriter] writeCycloneDxYaml: NOT YET IMPLEMENTED");
                break;
            case "SPDX_JSON":
                System.out.println("[SbomFileWriter] writeSpdxJson: NOT YET IMPLEMENTED");
                break;
            case "SPDX_TAG_VALUE":
                System.out.println("[SbomFileWriter] writeSpdxTagValue: NOT YET IMPLEMENTED");
                break;
            case "SPDX_YAML":
                System.out.println("[SbomFileWriter] writeSpdxYaml: NOT YET IMPLEMENTED");
                break;
            default:
                System.out.println("[SbomFileWriter] ERROR: Unsupported output format: " + format);
        }
    }

    private void writeCycloneDxJson() {
        try {
            // parse the input SBOM — supports both JSON and XML input
            Bom sbom = parseInputSbom();
            if (sbom == null) {
                System.out.println("[SbomFileWriter] ERROR: Could not parse input SBOM: " + inputFile.getPath());
                return;
            }

            // build a lookup map from purl string -> LicenseData for fast matching
            java.util.Map<String, LicenseData> licenseMap = new java.util.HashMap<>();
            for (LicenseData data : collectedData) {
                // IContentId.toString() gives "maven/mavencentral/org.slf4j/slf4j-api/1.7.32"
                // we need to match against the component's purl
                licenseMap.put(data.getId().toString(), data);
            }

            // enrich each component with license data
            if (sbom.getComponents() != null) {
                for (Component component : sbom.getComponents()) {
                    String purl = component.getPurl();
                    if (purl == null) continue;

                    // find matching license data by converting purl to IContentId string
                    LicenseData data = findMatchingLicenseData(purl, licenseMap);
                    if (data == null) continue;

                    // attach license to component if we got one back
                    if (data.getLicense() != null) {
                        License license = new License();
                        license.setId(data.getLicense());
                        LicenseChoice licenseChoice = new LicenseChoice();
                        licenseChoice.addLicense(license);
                        component.setLicenses(licenseChoice);
                    }

                    // attach dash status and url as custom properties
                    List<Property> properties = component.getProperties() != null
                            ? new ArrayList<>(component.getProperties())
                            : new ArrayList<>();

                    Property statusProp = new Property();
                    statusProp.setName("eclipse.dash.status");
                    statusProp.setValue(data.getStatus() == Status.Approved ? "approved" : "restricted");
                    properties.add(statusProp);

                    if (data.getUrl() != null) {
                        Property urlProp = new Property();
                        urlProp.setName("eclipse.dash.url");
                        urlProp.setValue(data.getUrl());
                        properties.add(urlProp);
                    }

                    component.setProperties(properties);
                }
            }

            // serialize enriched SBOM to JSON and write to output file
            String json = BomGeneratorFactory.createJson(Version.VERSION_14, sbom).toJsonString();
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(json);
            }
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(json);
            }

            System.out.println("[SbomFileWriter] Successfully wrote enriched SBOM to: " + outputFile.getPath());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // parse input file as either CycloneDX JSON or XML
    private Bom parseInputSbom() {
        String name = inputFile.getName().toLowerCase();
        try {
            if (name.endsWith(".json")) {
                return new JsonParser().parse(inputFile);
            } else if (name.endsWith(".xml")) {
                return new XmlParser().parse(inputFile);
            } else {
                System.out.println("[SbomFileWriter] ERROR: Input format not supported for enrichment: " + name);
                return null;
            }
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    // match a raw purl string against the IContentId-keyed license map
    private LicenseData findMatchingLicenseData(String purl, java.util.Map<String, LicenseData> licenseMap) {
        // convert the purl to an IContentId and compare toString()
        org.eclipse.dash.licenses.IContentId id = new org.eclipse.dash.licenses.PackageUrlIdParser().parseId(purl);
        if (id == null) return null;
        return licenseMap.get(id.toString());
    }

    private String detectOutputFormat() {
        String name = outputFile.getName().toLowerCase();
        if (name.endsWith(".xml")) return "CYCLONEDX_XML";
        if (name.endsWith(".yaml") || name.endsWith(".yml")) return "CYCLONEDX_YAML";
        if (name.endsWith(".spdx")) return "SPDX_TAG_VALUE";
        if (name.endsWith(".json")) return "CYCLONEDX_JSON";
        return "UNKNOWN";
    }
}