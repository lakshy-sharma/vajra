# Build variables
RELEASE_DIR=./release
SRC=./src

# Deployment variables
PACKAGE_NAME=vajra
VERSION=$(shell cat version)
DEB_SKEL=./deb_skel
DEPLOY_BINPATH=${DEB_BASE}/opt/${PACKAGE_NAME}

all: linux_amd64

linux_amd64: ARCH :=amd64
linux_amd64: DEB_BASE := ./$(PACKAGE_NAME)_$(VERSION)_$(ARCH)
linux_amd64:
	@echo "Building ${PACKAGE_NAME} - Version: ${VERSION} Architecture: ${ARCH}"
	@echo "============================================"
	cd ${SRC}/internal && go generate
	cd ${SRC} && GOOS=linux GOARCH=${ARCH} go build -ldflags="-s -w" -o ${PACKAGE_NAME} main.go
	mkdir -p ${RELEASE_DIR}
	mv ${SRC}/${PACKAGE_NAME} ${RELEASE_DIR}/${PACKAGE_NAME}
	upx --brute ${RELEASE_DIR}/${PACKAGE_NAME}

	@echo "Building deb package for ${PACKAGE_NAME}"
	cp -r ${DEB_SKEL} ${DEB_BASE}
	sed -i 's/<PACKAGE_NAME>/${PACKAGE_NAME}/' ${DEB_BASE}/DEBIAN/control
	sed -i 's/<VERSION>/${VERSION}/' ${DEB_BASE}/DEBIAN/control
	sed -i 's/<ARCH>/${ARCH}/' ${DEB_BASE}/DEBIAN/control
	cp ${RELEASE_DIR}/${PACKAGE_NAME} ${DEPLOY_BINPATH}/${PACKAGE_NAME}
	dpkg-deb --build ${DEB_BASE}
	mv ${DEB_BASE}.deb ${RELEASE_DIR}

	@echo "Cleaning build files"
	rm -r ${DEB_BASE}
	@echo "Build complete"
	@echo "============================================";

linux_arm64: ARCH :=arm64
linux_arm64: DEB_BASE := ./$(PACKAGE_NAME)_$(VERSION)_$(ARCH)
linux_arm64:
	@echo "Building ${PACKAGE_NAME} - Version: ${VERSION} Architecture: ${ARCH}"
	@echo "============================================"
	cd ${SRC}/internal && go generate
	cd ${SRC} && GOOS=linux GOARCH=${ARCH} go build -ldflags="-s -w" -o ${PACKAGE_NAME} main.go
	mkdir -p ${RELEASE_DIR}
	mv ${SRC}/${PACKAGE_NAME} ${RELEASE_DIR}/${PACKAGE_NAME}
	upx --brute ${RELEASE_DIR}/${PACKAGE_NAME}

	@echo "Building deb package for ${PACKAGE_NAME}"
	cp -r ${DEB_SKEL} ${DEB_BASE}
	sed -i 's/<PACKAGE_NAME>/${PACKAGE_NAME}/' ${DEB_BASE}/DEBIAN/control
	sed -i 's/<VERSION>/${VERSION}/' ${DEB_BASE}/DEBIAN/control
	sed -i 's/<ARCH>/${ARCH}/' ${DEB_BASE}/DEBIAN/control
	cp ${RELEASE_DIR}/${PACKAGE_NAME} ${DEPLOY_BINPATH}/${PACKAGE_NAME}
	dpkg-deb --build ${DEB_BASE}

	@echo "Cleaning build files"
	rm -r ${DEB_BASE}
	@echo "Build complete"
	@echo "============================================";