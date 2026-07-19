package org.eclipse.dash.licenses.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;

// Jackson: a general-purpose JSON/YAML toolkit. Used here only to peek inside a
// file far enough to tell whether it is SPDX or CycloneDX (see contentFamily).
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.eclipse.dash.licenses.IContentId;

/**
 * Entry point for reading SBOM files. This class only decides which SBOM family
 * a file belongs to and delegates the actual parsing to the format-specific
 * reader ({@link CycloneDXSbomReader} or {@link SpdxSbomReader}).
 *
 * The family is determined from the file extension, except for the ambiguous
 * ".json"/".yaml" cases which are disambiguated by peeking for an SPDX-only
 * "spdxVersion" field.
 */
// "implements IDependencyListReader" is a promise that this class provides a
// getContentIds() method. That shared contract is what lets the rest of the tool
// (e.g. Main) treat this reader, CycloneDXSbomReader, and SpdxSbomReader
// interchangeably without knowing which concrete one it is holding.
public class SbomFileReader implements IDependencyListReader {

    // The one file this reader is responsible for. "final" means once the
    // constructor sets it, it can never be swapped for a different file.
    private final File file;

    // Two shared Jackson readers, created once for the whole program ("static"):
    //   OBJECT_MAPPER understands JSON, YAML_MAPPER understands YAML.
    // They are only used to sniff a file's contents when the extension alone
    // (.json / .yaml) cannot tell us whether it is SPDX or CycloneDX.
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    // Constructor: runs when someone writes "new SbomFileReader(file)".
    // It refuses to build a reader for a file that does not exist, failing fast
    // with a clear FileNotFoundException instead of blowing up later during parsing.
    public SbomFileReader(File file) throws FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException(file.getPath());
        }
        // Store the passed-in file into this object's permanent field. "this.file"
        // is the field; plain "file" is the constructor's parameter (they share a
        // name, so "this." is needed to tell them apart).
        this.file = file;
    }

    // The single public method required by IDependencyListReader. It does NOT parse
    // anything itself: it works out the file's family, then hands the real work to
    // the matching specialist reader and returns whatever that reader produces.
    @Override
    public Collection<IContentId> getContentIds() {
        // Decide the family (CYCLONEDX / SPDX / UNKNOWN), then branch on it.
        switch (detectFamily(file)) {
            case CYCLONEDX:
                // Build a CycloneDX reader for this file and delegate to it.
                return new CycloneDXSbomReader(file).getContentIds();
            case SPDX:
                // Build an SPDX reader for this file and delegate to it.
                return new SpdxSbomReader(file).getContentIds();
            case UNKNOWN:
            default:
                // We could not recognise the file at all — fail loudly rather than
                // silently returning nothing, naming the offending file.
                throw new RuntimeException("Unsupported SBOM format for file: " + file.getPath());
        }
    }

    // Works out which family a file belongs to, mostly from its extension.
    private SbomFamily detectFamily(File file) {
        // Lower-case the filename so the extension checks below are case-insensitive
        // (so "Sbom.JSON" and "sbom.json" are treated the same).
        String name = file.getName().toLowerCase();

        // ".json" is ambiguous: both SPDX and CycloneDX use it. So we cannot decide
        // from the name alone — peek inside the file to tell them apart.
        if (name.endsWith(".json")) {
            return contentFamily(OBJECT_MAPPER, file);
        }
        // there are times when .rdf/.xml files are given a double extension to make it explicit
        // that it is both XML and RDF; both map to SPDX regardless. Check before plain ".xml".
        // (A file named "foo.rdf.xml" also ends with ".xml", so this MUST come first or the
        // ".xml" check below would grab it and mislabel it as CycloneDX.)
        if (name.endsWith(".rdf") || name.endsWith(".rdf.xml")) {
            return SbomFamily.SPDX;
        }
        // A plain ".xml" (that was not caught as ".rdf.xml" above) is CycloneDX XML.
        if (name.endsWith(".xml")) {
            return SbomFamily.CYCLONEDX;
        }
        // spdx tag-value files can sometimes be saved with a .txt extension instead of .spdx.
        // Either extension means SPDX tag-value.
        if (name.endsWith(".spdx") || name.endsWith(".txt")) {
            return SbomFamily.SPDX;
        }
        // ".yaml"/".yml" is ambiguous the same way ".json" is — peek inside to decide.
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return contentFamily(YAML_MAPPER, file);
        }

        // Nothing matched — we do not know what this file is.
        return SbomFamily.UNKNOWN;
    }

    // For the extensions shared by both families (.json, .yaml), the SPDX-only
    // "spdxVersion" field distinguishes SPDX from CycloneDX.
    private SbomFamily contentFamily(ObjectMapper mapper, File file) {
        try {
            // Read the file into a tree of nodes, then look at the top level only.
            JsonNode root = mapper.readTree(file);
            // Only SPDX documents carry a top-level "spdxVersion" field. If it is
            // present -> SPDX; if not -> assume CycloneDX. (This is the compact
            // if/else "ternary": condition ? valueIfTrue : valueIfFalse.)
            return root.has("spdxVersion") ? SbomFamily.SPDX : SbomFamily.CYCLONEDX;
        } catch (IOException e) {
            // If the file could not even be read/parsed as a tree, we cannot classify
            // it — report UNKNOWN, which getContentIds() turns into a clear error.
            return SbomFamily.UNKNOWN;
        }
    }

    // A small fixed set of named values used internally to represent the decision.
    // Using an enum (instead of, say, strings) means the switch in getContentIds()
    // is checked by the compiler and cannot be handed a typo'd value.
    private enum SbomFamily {
        CYCLONEDX,
        SPDX,
        UNKNOWN
    }
}
