package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;

import org.spdx.spdxRdfStore.RdfStore;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v2.SpdxConstantsCompatV2;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;

/**
 * Reads SPDX SBOMs (JSON, YAML, tag-value, and RDF/XML) and extracts the purl
 * external references of every package as {@link IContentId}s. The specific
 * variant is chosen from the file extension; callers that need to distinguish
 * SPDX from CycloneDX up front should do so before delegating here
 * (see {@link SbomFileReader}).
 */





/*
An SPDX file lists packages. Each package carries a list of external references. Each 
external reference has 3 parts:
- A category
- A type
- A locator
A purl is just one kind external reference. To find a purl, we dig: package->it's external
refs->the one whose category is "package-manager" and type is "purl"->read it's locator.  




*/
public class SpdxSbomReader implements IDependencyListReader {

    private final File file;

    //create two ObjectMappers. One is a plain one for JSON files and the other is a taught YAML (
    //via YAMLFactory) for YAML. PURL_PARSER is the sampe purl -> IContentId converter as always. 
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

    public SpdxSbomReader(File file) {
        this.file = file;
    }

    @Override
    public Collection<IContentId> getContentIds() {
        String name = file.getName().toLowerCase();
        // .rdf / .rdf.xml first: a double extension also ends with ".xml"
        if (name.endsWith(".rdf") || name.endsWith(".rdf.xml")) {
            return parseSpdxRdfXml(file);
        }
        if (name.endsWith(".json")) {
            return parseSpdxJson(file);
        }
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return parseSpdxYaml(file);
        }
        // spdx tag-value is sometimes saved with a .txt extension instead of .spdx
        if (name.endsWith(".spdx") || name.endsWith(".txt")) {
            return parseSpdxTagValue(file);
        }
        throw new RuntimeException("Unsupported SPDX SBOM format for file: " + file.getPath());
    }

    private List<IContentId> parseSpdxJson(File file) {
     
        try {
            //readTree(file) opens the file and converts the entirer JSON text into a tree of nodes. 
            //Root is the node at the very top. 
            JsonNode root = OBJECT_MAPPER.readTree(file);
            //Create an empty list "results". This is the basket we'll drop found purls into as we go.
            List<IContentId> results = new ArrayList<>();

            //root.path("pacakges") steps from the top of the tree into the "packages" section -> which
            //is an array (a list). Each item is a ginle packaged and the inside the loop we call the current
            //one pkg.
            for (JsonNode pkg : root.path("packages")) {
                //vist each of pkg's external refs individually calling the current one ref.
                for (JsonNode ref : pkg.path("externalRefs")) {
                    //for the ref being currently analyzed, pull out two of it's three parts. asText("") reads
                    // the fieldName out as plain text.

                    //the "" inside asText("") is a fallback, for if the field is missing, supply an empty string 
                    //instead of null
                    String category = ref.path("referenceCategory").asText("");
                    String type = ref.path("referenceType").asText("");

                    // SPDX 2.2 uses "PACKAGE-MANAGER"; SPDX 2.3 uses "PACKAGE_MANAGER" — accept both

                    //equalsIgnoreCase compares text whilst ignoring any capitalization 
                    if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
                            && type.equalsIgnoreCase("purl")) {

                        // referenceLocator holds the actual purl string, e.g. "pkg:maven..."

                        //grab the third part of the ref (it's referenceLocator) which holds the actual purl string. 
                        //Fallback is null which is what the next block checks for.
                        String purl = ref.path("referenceLocator").asText(null);

                        if (purl != null) { //only proceed if we actuallh have a locator string

                            //PURL_PARSER.parseId(purl) converts the raw purl text into a structured IContentId object
                            //which is what the standardized interal form Dash uses. This can come back null if the purl
                            //is malformed or a type Dash doesn't support
                            IContentId id = PURL_PARSER.parseId(purl);
                            // parseId can return null for malformed/unsupported purls — skip those
                            if (id != null) {
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

    //parseSpdxYaml is identical to parseSpdxJson with exactly one difference:
    //  JsonNode root = YAML_MAPPER.readTree(file);
    //It uses YAML_MAPPER.readTree(file) instead of general ObjectMapper
    private List<IContentId> parseSpdxYaml(File file) {
        try {
            JsonNode root = YAML_MAPPER.readTree(file);
            List<IContentId> results = new ArrayList<>();
            for (JsonNode pkg : root.path("packages")) {
                for (JsonNode ref : pkg.path("externalRefs")) {
                    String category = ref.path("referenceCategory").asText("");
                    String type = ref.path("referenceType").asText("");
                    if ((category.equalsIgnoreCase("PACKAGE-MANAGER") || category.equalsIgnoreCase("PACKAGE_MANAGER"))
                            && type.equalsIgnoreCase("purl")) {

                        String purl = ref.path("referenceLocator").asText(null);
                        if (purl != null) {
                            IContentId id = PURL_PARSER.parseId(purl);
                            if (id != null) {
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

    //parseSpdxTagValue has no tree at all; it's just text lines.
    //method reads through the file line by line and pull apart the lines we care about by hand. 
    private List<IContentId> parseSpdxTagValue(File file) {
        try {
            List<IContentId> results = new ArrayList<>();
            //Files.readAllLines read ths whole file and gives back a list of lines (each line as a seperate string).
            //The for loop then walks through them one line at a time calling the current one "line".
            //file.toPath() converts our File hanlde into the Path type this method wants, and StandCharsets.UTF_8 tells it
            //to read the byes as UTF-8 text (standard modern text encoding).
            for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {

                //If this line does NOT start with ExternalRef:, continue.
                //So every non-ExternalRef: line gets instantly skipped, and only ExternalRef: lines make it past this point.
                if (!line.startsWith("ExternalRef:")) continue;

                // Strip the "ExternalRef:" prefix and split into max. 3 tokens
                // Validate we have exactly 3 tokens, the right category (2.2 and 2.3 variants), and purl type.
                //parts[0] = "PACKAGE-MANAGER" (category)
                //parts[1] = "purl" (the type)
                //parts[2] = "pkg.maven/org.slf4j..." (the locator)
                String[] parts = line.substring("ExternalRef:".length()).trim().split("\\s+", 3);

                
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

    @SuppressWarnings("unchecked")
    private List<IContentId> parseSpdxRdfXml(File file) {
        //results is defined up here as opposed to inside the try block. By declaring results up here, it exists whehter
        //or not an error happens partway through. So if the loop collects two purls and then something throws, we would
        //still return those two rather than nothing. 
        List<IContentId> results = new ArrayList<>();
        try {
            // RdfStore from the SPDX library replaces all the manual Jena triple-walking.
            // loadModelFromFile parses the RDF/XML and returns the document URI.

            //RdfStore is an object form the SPDX library - it's reader-and-holder for RDF documents. new RdfStore creates
            //an empty one ready to load a file into. 
            RdfStore rdfStore = new RdfStore();
            
            //takes file.getPath() (the file's location as text) and reads + parses the RDF/XML file into the rdfStore. 
            //the false is an option flag the library accepts (it controls a create-vs-load behaviour). false means to just
            //load what's there. 
            //Returns a documentUri - a unique identifying string for the SPDX document it just loaded. 
            String documentUri = rdfStore.loadModelFromFile(file.getPath(), false);

            
            //getSpdxObjects(...) means "go through the loaded document and give me back every object of a certain type." Reading its arguments:
            // rdfStore — where to look (the store we just loaded the file into).
            // null — a "copy manager" slot we don't need here, so we pass nothing.
            // SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE — what type we want: Package objects. This constant is the library's internal name for "SPDX Package." 
            // So this argument is what makes it return packages rather than, say, files or licenses.
            // documentUri — which document (the id we got from the previous line).
            // null — another optional slot left empty.
            // So this call is: "from the document we loaded, hand me all the SPDX Packages."

            //getSpdxObjects(...) doesn't return a finished list — it returns a Stream, which is Java's idea of a lazy "pipeline" of results that you finish by collecting 
            // them. .collect(Collectors.toList()) is the standard "pour the pipeline into an ordinary List" step. You don't need to master Streams to follow this — 
            // just read the whole thing as "get all the packages as a list."

            //The (List<SpdxPackage>) part spsecifies a list of SpdxPackages. Verified by CLASS_SPDX_PACKAGE. This is the reason for the "@SuppressWarnings" line at the top.

            //End result of the whole line: packages is a normal List of SpdxPackage objects — the typed, ready-to-use packages from the file.
            List<SpdxPackage> packages = (List<SpdxPackage>) SpdxModelFactory

                    .getSpdxObjects(rdfStore, null, SpdxConstantsCompatV2.CLASS_SPDX_PACKAGE, documentUri, null)
                    .collect(Collectors.toList());

            //for each instance of packages (referred to as pkg):        
            for (SpdxPackage pkg : packages) {
                // getExternalRefs() gives typed ExternalRef objects — no manual property lookups
                for (ExternalRef ref : pkg.getExternalRefs()) {
                    // ReferenceCategory is an enum, so the library normalizes the
                    // SPDX 2.2 ("PACKAGE-MANAGER") vs 2.3 ("PACKAGE_MANAGER") difference for us.
                    // In SPDX RDF the reference type is the full listed-reference URI
                    // (e.g. http://spdx.org/rdf/references/purl), not the bare string "purl".

                    //for the current ref, get it's type as a URI string. Read left to right. 

                    //ref.getReferenceType() asks this ref for it's "type" object.
                    //getIndividualURI() from that type object read out it's full URI as text.
                    //we store both refs inside a variable refTypeUri so the next line can compare against it.
                    String refTypeUri = ref.getReferenceType().getIndividualURI();

                    //ref.getReferenceCategory() asks the ref for it's category. Checks if this ref's category is the package-manager category.
                    //and since the category is an enum, we have the ability to compare against one value with ==. 

                    //SpdxConstantsCompatV2.SPDX_LISTED_REFERENCE_TYPES_PREFIX is a constant holding the text "http://spdx.org/rdf/references/" — the standard beginning of these type 
                    // URIs.
                    //+ "purl" glues "purl" onto the end, building the complete expected URI: "http://spdx.org/rdf/references/purl".
                    //.equalsIgnoreCase(refTypeUri) compares that built string against the ref's actual refTypeUri from earlier, ignoring capitalization.

                    // So this condition is: "does this ref's type URI equal the official purl URI?"

                    // 1st pass (purl ref): refTypeUri is ".../purl" → matches → true.
                    // 2nd pass (CPE ref): refTypeUri is ".../cpe23Type" → does not match → false.
                    // Putting the two conditions together with &&:

                    // 1st pass (purl ref): true && true → true → we go inside the if.
                    // 2nd pass (CPE ref): false && (…) → false → we skip everything inside the if; this ref is ignored.
                    if (ref.getReferenceCategory() == ReferenceCategory.PACKAGE_MANAGER
                            && (SpdxConstantsCompatV2.SPDX_LISTED_REFERENCE_TYPES_PREFIX + "purl")
                                    .equalsIgnoreCase(refTypeUri)) {
                    
                        //ref.getReferenceLocator() returns "pkg:maven/org/slf4j...." 
                        //PURL_PARSER.parseId(...) turns that raw purl text into a structured IContentId object, and then store it in id.
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
}
