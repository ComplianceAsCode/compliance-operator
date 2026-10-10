package v1alpha1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Testing ComplianceScan type validation", func() {
	Context("GetScanTypeIfValid", func() {
		It("should accept valid Platform scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ScanTypePlatform,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})

		It("should accept valid Node scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: ScanTypeNode,
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})

		It("should accept Platform in lowercase", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: "platform",
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypePlatform))
		})

		It("should accept Node in uppercase", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: "NODE",
				},
			}
			scanType, err := scan.GetScanTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scanType).To(Equal(ScanTypeNode))
		})

		It("should reject invalid scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: "InvalidType",
				},
			}
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})

		It("should reject empty scan type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: "",
				},
			}
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})

		It("should reject typo in Platform", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScanType: "Plattform",
				},
			}
			_, err := scan.GetScanTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanType))
		})
	})

	Context("GetScannerTypeIfValid", func() {
		It("should accept valid OpenSCAP scanner type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: ScannerTypeOpenSCAP,
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeOpenSCAP))
		})

		It("should accept valid CEL scanner type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: ScannerTypeCEL,
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeCEL))
		})

		It("should accept OpenSCAP in lowercase", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: "openscap",
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeOpenSCAP))
		})

		It("should accept CEL in mixed case", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: "Cel",
				},
			}
			scannerType, err := scan.GetScannerTypeIfValid()
			Expect(err).To(BeNil())
			Expect(scannerType).To(Equal(ScannerTypeCEL))
		})

		It("should reject invalid scanner type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: "InvalidScanner",
				},
			}
			_, err := scan.GetScannerTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanerType))
		})

		It("should reject empty scanner type", func() {
			scan := &ComplianceScan{
				Spec: ComplianceScanSpec{
					ScannerType: "",
				},
			}
			_, err := scan.GetScannerTypeIfValid()
			Expect(err).To(Equal(ErrUnkownScanerType))
		})
	})
})
