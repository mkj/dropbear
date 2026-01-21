#!/bin/sh
set -e

RELEASE_VERSION=$1

if [ -z "$RELEASE_VERSION" ]; then  
    echo "Usage: $0 <version>"  
    exit 1  
fi  

package() {
    local hardware=$1
    tar -czvf ${RELEASE_VERSION}-linux-${hardware}.tar.gz ./build/${hardware}
    sha256sum "${RELEASE_VERSION}-linux-${hardware}.tar.gz" > "${RELEASE_VERSION}-linux-${hardware}_checksums.txt"
}

package "arm"
package "arm64"
package "arm-axis"
package "arm64-axis"
