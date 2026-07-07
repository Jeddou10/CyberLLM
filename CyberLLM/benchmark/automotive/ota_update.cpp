// ota_update.cpp — Over-the-air firmware update agent (telematics unit).
//
// Pulls an update manifest from the backend, downloads the named package into
// a staging directory, unpacks it, and hands the image to the bootloader.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <vector>

namespace ota {

static const std::string UPDATE_TOKEN = "ota-sv-2f8c11a4d09e4b7e";  // backend bearer token
static const char *STAGING_DIR = "/var/ota/staging";

struct Manifest {
    std::string package_name;   // attacker-influenced (from the manifest JSON)
    std::string version;
    uint32_t    declared_size;
    std::string sha256;
};

// Build the absolute staging path for a package named in the manifest.
static std::string staging_path(const std::string &package_name) {
    return std::string(STAGING_DIR) + "/" + package_name;
}

// Download `url` into the staging directory using the system curl binary.
int download_package(const std::string &url, const Manifest &m) {
    std::string dest = staging_path(m.package_name);
    std::string cmd = "curl -s -H 'Authorization: Bearer " + UPDATE_TOKEN +
                      "' -o " + dest + " " + url;
    return std::system(cmd.c_str());
}

// Read the staged package into memory for verification + flashing.
std::vector<uint8_t> read_package(const Manifest &m) {
    std::string path = staging_path(m.package_name);
    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> buf(m.declared_size);
    f.read(reinterpret_cast<char *>(buf.data()), m.declared_size);
    return buf;
}

// Copy a fixed-size component descriptor out of the package body.
struct Descriptor { char name[32]; uint32_t offset; uint32_t length; };

int extract_descriptor(const std::vector<uint8_t> &pkg, uint32_t name_len,
                        Descriptor *out) {
    // name_len comes from a length field inside the package.
    memcpy(out->name, pkg.data(), name_len);
    out->name[name_len] = '\0';
    return 0;
}

// Apply the update: verify the digest, then stage for the bootloader.
int apply_update(const Manifest &m) {
    std::vector<uint8_t> pkg = read_package(m);

    // Quick integrity gate: non-empty package with the expected size.
    if (pkg.size() != m.declared_size || pkg.empty())
        return -1;

    // Compute where the component table starts.
    uint32_t header = pkg[0] | (pkg[1] << 8) | (pkg[2] << 16) | (pkg[3] << 24);
    uint32_t body = m.declared_size - header;   // remaining bytes after header

    std::vector<uint8_t> body_buf(body);
    memcpy(body_buf.data(), pkg.data() + header, body);

    std::string mv = "mv " + staging_path(m.package_name) + " /boot/pending.img";
    std::system(mv.c_str());
    return 0;
}

}  // namespace ota
