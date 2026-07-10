package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
//import java.util.stream.Collectors;

//import org.apache.commons.codec.language.bm.Lang;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.Parser;
import org.cyclonedx.parsers.XmlParser;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

//import jakarta.annotation.Resource;

import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
// import org.apache.jena.rdf.model.Model;
// import org.apache.jena.rdf.model.ModelFactory;
// import org.apache.jena.rdf.model.Property;
// import org.apache.jena.rdf.model.ResIterator;
// import org.apache.jena.rdf.model.StmtIterator;
//import org.apache.jena.riot.RDFDataMgr;

import java.util.stream.Collectors;
import org.spdx.spdxRdfStore.RdfStore;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;


public class SbomFileReader implements IDependencyListReader {

    private final File file;
    
    public SbomFileReader(File file) throws FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException(file.getPath());
        }
        this.file = file;
    }

    @Override
    public Collection<IContentId> getContentIds() {
        SbomFormat format = detectFormat(file);

        switch (format) {
            case CYCLONEDX_JSON:
                return parseCycloneDxJson(file);
            case CYCLONEDX_XML:
                return parseCycloneDxXml(file);
            case SPDX_JSON:
                return parseSpdxJson(file);
            case SPDX_TAG_VALUE:
                return parseSpdxTagValue(file);
            case CYCLONEDX_YAML:
                return parseCycloneDxYaml(file);
            case SPDX_YAML:
                return parseSpdxYaml(file);
            case SPDX_RDF_XML:
                return parseSpdxRdfXml(file);
            case UNKNOWN:
            default:
                throw new RuntimeException("Unsupported SBOM format for file: " + file.getPath());
        }
    }

    private SbomFormat detectFormat(File file) {
        String name = file.getName().toLowerCase();

        if (name.endsWith(".json")) {
            return detectJsonFormat(file);
        }
        //there are times when .rdf/xml files are given a double extension to make it explicit that it
        //is both XML and RDF SBOM types. But both map to the same SBOM type regardless
        if (name.endsWith(".rdf") || name.endsWith(".rdf.xml")){
            return SbomFormat.SPDX_RDF_XML;
        }
        if (name.endsWith(".xml")) {
            return SbomFormat.CYCLONEDX_XML;
        }
        //also there are times when spdx tag-value files can sometimes be saved with a .txt extension
        //instead of .spdx
        if (name.endsWith(".spdx") || name.endsWith(".txt")) {
            return SbomFormat.SPDX_TAG_VALUE;
        }
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return detectYamlFormat(file);
        }
        
        return SbomFormat.UNKNOWN;
    }

    // Distinguishes CycloneDX JSON ("bomFormat" field) from SPDX JSON ("spdxVersion" field).
    private SbomFormat detectJsonFormat(File file) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(file);  // use shared instance
            if (root.has("spdxVersion")) {
                return SbomFormat.SPDX_JSON;
            }
            return SbomFormat.CYCLONEDX_JSON;
        } catch (IOException e) {
            return SbomFormat.UNKNOWN;
        }
    }

   
    private SbomFormat detectYamlFormat(File file) {
        try {
            JsonNode root = YAML_MAPPER.readTree(file);  // use shared instance
            if (root.has("spdxVersion")) {
                return SbomFormat.SPDX_YAML;
            }
            return SbomFormat.CYCLONEDX_YAML;
        } catch (IOException e) {
            return SbomFormat.UNKNOWN;
        }
    }

   private List<IContentId> parseCycloneDxJson(File file) {

        var parser = new JsonParser();
        return ParseCycloneDx(file, parser);
    }

   private List<IContentId> ParseCycloneDx(File file, Parser parser) {
    try {
        var sbom = parser.parse(file);
        //return sbom.getDependencies().stream().map(each->new PackageUrlIdParser().parseId(each.getRef())).collect(Collectors.toList());
        List<IContentId> results = new ArrayList<>();
        if (sbom.getMetadata() != null && sbom.getMetadata().getComponent() != null){
            IContentId id = PURL_PARSER.parseId(sbom.getMetadata().getComponent().getPurl());
            if (id != null){
                results.add(id);
            }
        }
        if (sbom.getComponents() != null){
            for (var component : sbom.getComponents()) {
                IContentId id = PURL_PARSER.parseId(component.getPurl());
                if (id!= null){
                    results.add(id);
                }
            }
        }
        
        return results;
    }
    catch (ParseException e) {
        e.printStackTrace();
    }

    return new ArrayList<>();
   }

    private List<IContentId> parseCycloneDxXml(File file) {
        var parser = new XmlParser();
        return ParseCycloneDx(file, parser);
    }

    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

    private List<IContentId> parseSpdxJson(File file) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(file);
            List<IContentId> results = new ArrayList<>();

            for (JsonNode pkg : root.path("packages")) {
                for (JsonNode ref : pkg.path("externalRefs")) {
                    String category = ref.path("referenceCategory").asText("");
                    String type = ref.path("referenceType").asText("");

                    // SPDX versoin 2.2 uses "PACKAGE-MANAGER"; SPDX 2.3 uses version "PACKAGE_MANAGER" — accept both equally
                    if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
                            && type.equalsIgnoreCase("purl")) {

                        // referenceLocator holds the actual purl string, e.g. "pkg:maven..."
                        String purl = ref.path("referenceLocator").asText(null);

                        if (purl != null) {
                            // Convert the raw purl string into a structured IContentId
                            IContentId id = PURL_PARSER.parseId(purl);

                            // parseId can return null for malformed/unsupported purls — skip those
                            if (id != null){
                                results.add(id);
                            } 
                        }
                    }
                }
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }
    private static final ObjectMapper YAML_MAPPER  = new ObjectMapper(new YAMLFactory());
    private List<IContentId> parseSpdxYaml(File file){
        try{
            JsonNode root = YAML_MAPPER.readTree(file);
            List<IContentId> results = new ArrayList<>();
            for (JsonNode pkg: root.path("packages")){
                for (JsonNode ref : pkg.path("externalRefs")){
                    String category = ref.path("referenceCategory").asText("");
                    String type = ref.path("referenceType").asText("");
                    if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
                            && type.equalsIgnoreCase("purl")) {

                        String purl = ref.path("referenceLocator").asText(null);
                        if (purl != null) {
                            IContentId id = PURL_PARSER.parseId(purl);
                            if (id != null) results.add(id);
                        }
                    }
                
                }
            }
            return results;
        }
        catch (IOException e){
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    private List<IContentId> parseSpdxTagValue(File file) {
        try {
            List<IContentId> results = new ArrayList<>();

            for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
                // Only process ExternalRef lines — skip everything else (metadata, relationships, etc.)
                if (!line.startsWith("ExternalRef:")) continue;

                // Strip the "ExternalRef:" prefix and split into max. 3 tokens
                String[] parts = line.substring("ExternalRef:".length()).trim().split("\\s+", 3);

                // Validate we have exactly 3 tokens, the right category (2.2 and 2.3 variants), and purl type
                if (parts.length == 3
                        && (parts[0].equalsIgnoreCase("PACKAGE-MANAGER") || parts[0].equalsIgnoreCase("PACKAGE_MANAGER"))
                        && parts[1].equalsIgnoreCase("purl")) {

                    // parts[2] is the purl locator — parse it into a structured IContentId
                    IContentId id = PURL_PARSER.parseId(parts[2]);

                    // parseId can return null for malformed/unsupported purls — skip those
                    if (id != null) results.add(id);
                }
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }
    private List<IContentId> parseCycloneDxYaml(File file) {
        try {
            //create a Jackson parser that understands YAML formats instead of JSON. 
            ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory()); 
            //now read the entire YAML file into a tree of JsonNode ojbects.
            JsonNode root = yamlMapper.readTree(file);

            List<IContentId> results = new ArrayList<>();
            //now navigate to the components key in the YAML file (name, purl...)
            for (JsonNode component : root.path("components")) {
                //for each component grab the purl field as a string - if DNE, return null instead of an error.
                String purl = component.path("purl").asText(null);
                if (purl != null) {
                    //convvert the raw purl string into a structured IContentId object 
                    IContentId id = PURL_PARSER.parseId(purl);
                    if (id != null){
                        results.add(id);
                    } 
                }
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }
    @SuppressWarnings("unchecked")
    private List<IContentId> parseSpdxRdfXml(File file) {
        List<IContentId> results = new ArrayList<>();
        try {
            // RdfStore from the SPDX library replaces all the manual Jena triple-walking.
            // loadModelFromFile parses the RDF/XML and returns the document URI.
            RdfStore rdfStore = new RdfStore();
            String documentUri = rdfStore.loadModelFromFile(file.getPath(), false);

            // Pull every SPDX package out of the parsed document as typed objects
            // instead of iterating raw RDF subjects/statements.
            List<SpdxPackage> packages = (List<SpdxPackage>) SpdxModelFactory
                    .getSpdxObjects(rdfStore, null, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE, documentUri, null)
                    .collect(Collectors.toList());

            for (SpdxPackage pkg : packages) {
                // getExternalRefs() gives typed ExternalRef objects — no manual property lookups
                for (ExternalRef ref : pkg.getExternalRefs()) {
                    // ReferenceCategory is an enum, so the library normalizes the
                    // SPDX 2.2 ("PACKAGE-MANAGER") vs 2.3 ("PACKAGE_MANAGER") difference for us.
                    // In SPDX RDF the reference type is the full listed-reference URI
                    // (e.g. http://spdx.org/rdf/references/purl), not the bare string "purl".
                    String refTypeUri = ref.getReferenceType().getIndividualURI();
                    if (ref.getReferenceCategory() == ReferenceCategory.PACKAGE_MANAGER
                            && (SpdxConstantsCompatV2.SPDX_LISTED_REFERENCE_TYPES_PREFIX + "purl")
                                    .equalsIgnoreCase(refTypeUri)) {
                        IContentId id = PURL_PARSER.parseId(ref.getReferenceLocator());
                        if (id != null) {
                            results.add(id);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return results;
    }
    // private List<IContentId> parseSpdxRdfXml(File file){
    //     List<IContentId> results = new ArrayList<>();
    //     try{
    //         //create an empty Jena RDF graph, often referred to as a "model" hence the name
    //         Model model = ModelFactory.createDefaultModel();
    //         model.read(file.getPath(), "RDF/XML");
    //         // SPDX RDF uses this predicate for external references

    //         //locate and assign properties externalRef, referenceCategory, referenceType and
    //         //referenceLocator for purl extraction

    //         //SPDX's definitions of these properties
    //         Property externalRefProp = model.createProperty( 
    //             "https://spdx.org/rdf/terms#externalRef");
    //         Property refCategoryProp = model.createProperty(
    //             "https://spdx.org/rdf/terms#referenceCategory");
    //         Property refTypeProp = model.createProperty(
    //             "https://spdx.org/rdf/terms#referenceType");
    //         Property refLocatorProp = model.createProperty(
    //             "https://spdx.org/rdf/terms#referenceLocator");
            
    //         //searches the graph for a subject that has at least one externalRef relationship.
    //         //ResIterator is the iterator for resources in the library
    //         ResIterator packages = model.listSubjectsWithProperty(externalRefProp);
    //         //hasNext() just checks if the next element exists or not

    //         //packages is a list of every package in the RDF file that has at least one 
    //         //external reference (can be multiple)
    //         while (packages.hasNext()) {
    //             //grabs the next package from the list and store it in pkg. The whole 
    //             //Resource name is used to prevent naming conflicts with 
    //             //jakarta.annotation.Resource
    //             org.apache.jena.rdf.model.Resource pkg = packages.nextResource();

    //             //asks this package to give all externalRerf relationships. A package can have
    //             //many - refs is now a list of all them
    //             StmtIterator refs = pkg.listProperties(externalRefProp);
    //             //are there more externalRefs for this package? If yes continue. 
    //             while (refs.hasNext()) {
    //                 //refs.next() get the next external ref triple
    //                 //.getObject() grab the third part which is the external ref node itself
    //                 //.asResource() cast it so it's properties can be queried and then stored in ref
    //                 org.apache.jena.rdf.model.Resource ref = refs.next().getObject().asResource();
    //                 //get the category and type from the ref
    //                 //e.g. category = "PACKAGE_MANAGER", type = "purl"
    //                 var categoryProp = ref.getProperty(refCategoryProp);
    //                 var typeProp = ref.getProperty(refTypeProp);
    //                 if (categoryProp == null || typeProp == null) continue;
    //                 String category = ref.getProperty(refCategoryProp).getString();
    //                 String type     = ref.getProperty(refTypeProp).getString();
    //                 //then skip anything that is not a purl such as CVEs or checksums
    //                 //handle both SPDX 2.2 versoin and SPDX 2.3 version of pakcage manager
    //                 if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
    //                         && type.equalsIgnoreCase("purl")) {
    //                     //get the actual purl
    //                     String purl = ref.getProperty(refLocatorProp).getString();
    //                     //convert to IContentId
    //                     IContentId id = PURL_PARSER.parseId(purl);
    //                     if (id != null){
    //                         results.add(id);
    //                     } 
    //                 }
    //             }
    //         }
    //     } 
    //     catch (Exception e) {
    //         e.printStackTrace();
    //     }
    //     return results;
    // }
    



    private enum SbomFormat {
        CYCLONEDX_XML,
        CYCLONEDX_JSON,
        CYCLONEDX_YAML,
        SPDX_JSON,
        SPDX_TAG_VALUE,
        SPDX_YAML,
        SPDX_RDF_XML,
        UNKNOWN
    }
}
