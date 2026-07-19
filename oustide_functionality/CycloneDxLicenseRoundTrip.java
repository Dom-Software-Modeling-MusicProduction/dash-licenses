
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.parsers.JsonParser;

/**
 * Standalone proof-of-concept. Deliberately has ZERO dependencies on the
 * Eclipse Dash License Tool — it only uses the CycloneDX library plus the JDK.
 *
 * It proves the library can do the full round-trip we need:
 *   1. LOAD   an existing CycloneDX SBOM from disk,
 *   2. CHANGE the license information on every component,
 *   3. WRITE  the modified SBOM back out to a new file,
 *   4. VERIFY by re-loading the written file and reading the licenses back.
 *
 * Usage:  java CycloneDxLicenseRoundTrip <input.json> <output.json> [newLicenseId]
 * Defaults: sample-sbom.json -> sample-sbom.enriched.json, license "MIT".
 */
public class CycloneDxLicenseRoundTrip {

    public static void main(String[] args) throws Exception { //the input is a string array "args" 
        //args.length > 0 checks if the user supplied at least one word. If so, use the first word.
        //If not, use the fallback "sample-sbom.json". If the user typed nothing, sample-sbom.json
        //will be selected.

        //always takes 3 arguments

        String inputPath  = args.length > 0 ? args[0] : "sample-sbom.json"; 
        //Same pattern for outputPath (the file to write). If the user supplied a second word "args[1]"
        //use it; otherwise default to sample-sbom.enriched.json
        String outputPath = args.length > 1 ? args[1] : "sample-sbom.enriched.json";
        //Stores the third word "args[2]" and use it; otherwise use the license "MIT"
        String newLicense = args.length > 2 ? args[2] : "MIT";

        //takes the argument text for inputPath and points to something named that in the current folder
        File inputFile  = new File(inputPath);
        //takes the argument text for outputPath and points to something named that in the current folder
        File outputFile = new File(outputPath);

        // 1. LOAD FILE

        //make a new JsonParser reader object and .parse(InputFile) tells the reader to go open the File
        //inputFile and read it as a CycloneDX Json. If there is no file for inputFile, an error will show
        Bom bom = new JsonParser().parse(inputFile);
        System.out.println("Loaded '" + inputPath + "'");
        System.out.println("Licenses BEFORE:");
        printLicenses(bom);

        // 2. CHANGE -----------------------------------------------------------
        // Overwrite each component's license with a single new license id.
        List<Component> components = bom.getComponents() != null
                ? bom.getComponents() : new ArrayList<>();
        for (Component component : components) {
            License license = new License();
            license.setId(newLicense);                 // e.g. "MIT"
            LicenseChoice choice = new LicenseChoice();
            choice.addLicense(license);
            component.setLicenses(choice);
        }
        System.out.println("\nSet every component's license to '" + newLicense + "'.");

        // 3. WRITE ------------------------------------------------------------
        String json = BomGeneratorFactory.createJson(Version.VERSION_14, bom).toJsonString();
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(json);
        }
        System.out.println("Wrote modified SBOM to '" + outputPath + "'.");

        // 4. VERIFY -----------------------------------------------------------
        // Re-parse the file we just wrote so the proof is end-to-end, not just
        // an in-memory object we happen to still hold.
        Bom reloaded = new JsonParser().parse(outputFile);
        System.out.println("\nLicenses AFTER (re-loaded from the written file):");
        printLicenses(reloaded);

        boolean allChanged = true;
        for (Component component : reloaded.getComponents()) {
            String id = firstLicenseId(component);
            if (!newLicense.equals(id)) {
                allChanged = false;
            }
        }
        System.out.println("\nRound-trip verification: "
                + (allChanged ? "PASS - every component now reports '" + newLicense + "'."
                              : "FAIL - some component did not carry the new license."));
    }

    private static void printLicenses(Bom bom) {
        if (bom.getComponents() == null) {
            System.out.println("  (no components)");
            return;
        }
        //a for loop; go through the list returned by bom.getComponents and call the current one 
        //component. 
        for (Component component : bom.getComponents()) {
            //print the following per component:
                //" - " is a fixed prefex so each line starts with a small indent and dash
                //"component.getName()" asks the component for it's name
                //then "@" as a seperator between the name and version
                //"component.getVersion()" asks for the version
                //then " license="
                //"firstLicenseId(component)" calls another helper method that digs into the license
                //id out of this component, and handling the case where it has none.
            System.out.println("  - " + component.getName() + "@" + component.getVersion()
                    + "  license=" + firstLicenseId(component));
        }
    }

    private static String firstLicenseId(Component component) { //method requires one input: component
        //asks the component for it's associated licenses.
        LicenseChoice choice = component.getLicenses();
        if (choice == null || choice.getLicenses() == null || choice.getLicenses().isEmpty()) {
            return "(none)";
        }
        //reads left to right - take the wrapper(choice), get it's licenses, grab the first one in the list
        //and get the license's id. 
        return choice.getLicenses().get(0).getId();
    }
}
