package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.Parser;
import org.cyclonedx.parsers.XmlParser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.eclipse.dash.licenses.IContentId;
import org.eclipse.dash.licenses.PackageUrlIdParser;

/**
 * Reads CycloneDX SBOMs (JSON, XML, and YAML) and extracts the package URLs of
 * every component as IContentIds. The specific variant is chosen from the
 * file extension; callers that need to distinguish CycloneDX from SPDX up front
 * should do so before delegating here
 */

//the "implements IDependencyListReader" part is important. It's a promise that this
//class will have a getContentIds method so it can be used anywhere the old one was 
//used. 
public class CycloneDXSbomReader implements IDependencyListReader { 

    //assign a piece of data that's private to the class and it's final, which means it's
    //value can never be reassigned.
    private final File file;

    //create a static object (belonging to the class as a whole, not each individual object) so
    //there is one shared PURL_Parser for the entire program, no matter how many reader objects
    //get created. 
    private static final PackageUrlIdParser PURL_PARSER = new PackageUrlIdParser();

    public CycloneDXSbomReader(File file) {
        this.file = file;
    }

    @Override
    public Collection<IContentId> getContentIds() {
        String name = file.getName().toLowerCase();
        if (name.endsWith(".json")) {
            return parse(file, new JsonParser());
        }
        if (name.endsWith(".xml")) {
            return parse(file, new XmlParser());
        }
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return parseYaml(file);
        }
        throw new RuntimeException("Unsupported CycloneDX SBOM format for file: " + file.getPath());
    }

    // Shared path for the CycloneDX library parsers (JSON and XML). Includes the
    // top-level metadata.component (the SBOM's own subject) plus every component.

    //takes two inputs: the file and a Parser. Parser is the general type that both JsonParser and XmlParser
    //count as, so the method can be used to server both cases.
    private List<IContentId> parse(File file, Parser parser) { 
        try {
            //call the given parser's .parse(file) to read the SBOM. "var" is a shorthand: instead of writing
            //the full type name, var tells Java to figure out the type automatically.
            var sbom = parser.parse(file);

            //create an empty list called results to collect the ids we find. List<IContentId> on the left is the
            //type; new ArrayList<>() on the right side is the actual empty list object. <> so you don't repeat
            //IContentId.
            List<IContentId> results = new ArrayList<>();
            if (sbom.getMetadata() != null && sbom.getMetadata().getComponent() != null) {
                //sbom.getMetadata().getComponent().getPurl() chains calls to dig out that component's purl
                //string, then PURL_PARSER.parseId(...) converts it into an IContentId (or null if the purl is
                //malformed)
                IContentId id = PURL_PARSER.parseId(sbom.getMetadata().getComponent().getPurl());
                if (id != null) {
                    results.add(id);
                }
            }
            //only proceed if there's actually a component list
            if (sbom.getComponents() != null) {
                //loop over each component - grab it's purl, parse it into an id and if the id isn't null - add it
                //to results.
                for (var component : sbom.getComponents()) {
                    IContentId id = PURL_PARSER.parseId(component.getPurl());
                    if (id != null) {
                        results.add(id);
                    }
                }
            }
            return results;
        } catch (ParseException e) {
            e.printStackTrace();
        }
        //if successful, return the new ArrayList<>()
        return new ArrayList<>();
    }

    // The CycloneDX library has no YAML parser, so walk the tree with Jackson.
    private List<IContentId> parseYaml(File file) {
        try {
            //create a new Jackson reader configured to interpret YAML (the YAML Factory is what teaches the general
            //ObjectMapper to speak to YAML specifically).
            ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
            
            //read the whole file into a tree of JsonNodes. Root is the top of the tree.
            JsonNode root = yamlMapper.readTree(file);

            List<IContentId> results = new ArrayList<>();

            //root.path("components") -> navigate into the tree to the "components" section (the list of components in the
            //YAML). .path(fieldName: "components") means go to the field with this name.
            for (JsonNode component : root.path("components")) {
             
                //component.path("purl") navigates into this component node to it's "purl" field. 
                String purl = component.path("purl").asText(null);
                if (purl != null) {
                    IContentId id = PURL_PARSER.parseId(purl);
                    if (id != null) {
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
}
