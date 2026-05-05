package compliance

// Minimal PDF writer — no external dependencies, no font files required.
// Uses standard PDF Type1 core fonts (Helvetica, Helvetica-Bold, Courier)
// which are part of the PDF specification and available in all PDF viewers.

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// renderPDF generates a compliance report as a PDF byte slice.
func renderPDF(r *Report) ([]byte, error) {
	p := newPDFWriter()
	d := r.Data

	p.begin()

	// Broken chain banner — prominent red box at top.
	if !d.ChainAttestation.OK {
		p.addPage()
		p.colorRect(15, 15, 180, 22, 0.86, 0.20, 0.20)
		p.setTextColor(1, 1, 1)
		p.setFont("Helvetica-Bold", 14)
		p.text(20, 30, "⚠  AUDIT CHAIN INTEGRITY FAILURE — REPORT NOT VALID AS EVIDENCE")
		p.setTextColor(0, 0, 0)
		p.setFont("Helvetica", 10)
		p.text(20, 44, "The tamper-evident audit chain is broken. This report must not be submitted as compliance evidence.")
		if d.ChainAttestation.BrokenAtID != "" {
			p.text(20, 56, fmt.Sprintf("First broken event: %s", d.ChainAttestation.BrokenAtID))
		}
		p.setY(70)
		p.hline(15, p.y, 180)
		p.setY(p.y + 8)
	} else {
		p.addPage()
	}

	// Title
	fwLabel := frameworkLabel(d.Framework, d.FrameworkVersions)
	p.setFont("Helvetica-Bold", 20)
	p.text(15, p.y, fmt.Sprintf("TASS Compliance Report — %s", fwLabel))
	p.setY(p.y + 14)

	p.setFont("Helvetica", 10)
	p.text(15, p.y, fmt.Sprintf("Repository: %s", d.Repo))
	p.setY(p.y + 6)
	p.text(15, p.y, fmt.Sprintf("Generated: %s    TASS version: %s", r.GenerationTs.UTC().Format(time.RFC3339), r.TassVersion))
	p.setY(p.y + 6)
	p.text(15, p.y, fmt.Sprintf("Report hash: %s", r.ReportHash))
	p.setY(p.y + 10)
	p.hline(15, p.y, 180)
	p.setY(p.y + 8)

	// 1. Executive Summary
	p.sectionHeader("1. Executive Summary")
	s := d.Summary
	rows := [][]string{
		{"Metric", "Value"},
		{"Total scans", fmt.Sprintf("%d", s.TotalScans)},
		{"Total capabilities", fmt.Sprintf("%d", s.TotalCapabilities)},
		{"Confirmed", fmt.Sprintf("%d", s.ConfirmedCount)},
		{"Reverted", fmt.Sprintf("%d", s.RevertedCount)},
		{"Unconfirmed (residual risk)", fmt.Sprintf("%d", s.UnconfirmedCount)},
		{"Audit chain events checked", fmt.Sprintf("%d", s.ChainCheckedCount)},
	}
	chainRow := []string{"Audit chain status", "INTACT"}
	if !s.AuditChainIntact {
		chainRow[1] = "BROKEN"
	}
	rows = append(rows, chainRow)
	p.table(rows, []float64{120, 65})

	// 2. Detected Capabilities
	p.sectionHeader("2. Detected Capabilities")
	if len(d.Capabilities) == 0 {
		p.body("No capabilities detected in the selected period.")
	} else {
		rows := [][]string{{"ID (short)", "Name", "Category", "Decision", "Confirmed By"}}
		for _, c := range d.Capabilities {
			rows = append(rows, []string{
				shortID(c.ID), c.Name, c.Category, c.Decision, c.ConfirmedBy,
			})
		}
		p.table(rows, []float64{40, 60, 35, 25, 30})
	}

	// 3. Control Coverage Matrix
	p.sectionHeader("3. Control Coverage Matrix")
	if len(d.ControlMatrix) == 0 {
		p.body("No capabilities mapped to controls.")
	} else {
		rows := [][]string{{"Framework", "Control ID", "Evidence", "Capability Count"}}
		for _, e := range d.ControlMatrix {
			evid := "Yes"
			if !e.HasEvidence {
				evid = "No confirmed"
			}
			rows = append(rows, []string{
				e.Framework, e.ControlID, evid, fmt.Sprintf("%d", len(e.CapabilityIDs)),
			})
		}
		p.table(rows, []float64{35, 35, 30, 30})
	}

	// 4. Unconfirmed (Residual Risk)
	p.sectionHeader("4. Unconfirmed Capabilities — Residual Risk")
	if len(d.Unconfirmed) == 0 {
		p.body("All detected capabilities have been reviewed.")
	} else {
		p.bodyWarn(fmt.Sprintf("ACTION REQUIRED: %d capabilities have not been confirmed or reverted.", len(d.Unconfirmed)))
		rows := [][]string{{"ID (short)", "Name", "Category"}}
		for _, c := range d.Unconfirmed {
			rows = append(rows, []string{shortID(c.ID), c.Name, c.Category})
		}
		p.table(rows, []float64{50, 80, 40})
	}

	// 5. TASS Product Controls
	p.sectionHeader("5. TASS Product Controls — Self-Attestation")
	rows2 := [][]string{{"Control", "Implemented By", "Control IDs"}}
	for _, tc := range d.TassControls {
		rows2 = append(rows2, []string{tc.Name, tc.ImplementedBy, controlRefsSummary(tc.ControlRefs)})
	}
	p.table(rows2, []float64{45, 65, 80})

	// 6. Audit Chain Attestation
	p.sectionHeader("6. Audit Chain Attestation")
	ca := d.ChainAttestation
	if ca.OK {
		p.body(fmt.Sprintf("Chain intact. %d events verified.", ca.CheckedCount))
		p.body(fmt.Sprintf("Chain head hash: %s", ca.ChainHeadHash))
	} else {
		p.bodyWarn("CHAIN BROKEN — do not submit as audit evidence.")
		if ca.BrokenAtID != "" {
			p.body(fmt.Sprintf("First broken event: %s", ca.BrokenAtID))
		}
	}

	// 7. Framework Versions
	p.sectionHeader("7. Framework Versions")
	fvRows := [][]string{{"Key", "Framework", "Authority"}}
	for _, fv := range d.FrameworkVersions {
		fvRows = append(fvRows, []string{fv.Key, fv.Name, fv.Authority})
	}
	p.table(fvRows, []float64{30, 120, 40})

	return p.end()
}

// --- Minimal PDF writer ---

type pdfWriter struct {
	buf     bytes.Buffer
	objs    []string   // object bodies indexed by (objNum-1)
	offsets []int      // byte offsets of each object
	pages   []int      // page object numbers
	y       float64    // current Y position in mm on current page
	pageH   float64    // page height mm (A4=297)
	pageW   float64    // page width mm (A4=210)
	margin  float64    // page margin mm
	streams []string   // one content stream per page
	curFont string
	curSize float64
	txR, txG, txB float64 // text color
}

func newPDFWriter() *pdfWriter {
	return &pdfWriter{
		pageH:  297,
		pageW:  210,
		margin: 15,
		curFont: "Helvetica",
		curSize: 10,
	}
}

func (p *pdfWriter) begin() {
	// Catalog = obj 1, Pages = obj 2 (reserved, filled on end())
	p.objs = append(p.objs, "", "") // placeholders for catalog + pages
}

func (p *pdfWriter) addPage() {
	p.streams = append(p.streams, "")
	p.y = p.margin + 10
}

func (p *pdfWriter) curStream() *string {
	if len(p.streams) == 0 {
		p.addPage()
	}
	return &p.streams[len(p.streams)-1]
}

func (p *pdfWriter) emit(cmd string) {
	s := p.curStream()
	*s += cmd
}

func (p *pdfWriter) setFont(name string, size float64) {
	p.curFont = name
	p.curSize = size
	fn := fontAlias(name)
	p.emit(fmt.Sprintf("BT /F%s %.1f Tf ET\n", fn, mmToPt(size)))
}

func (p *pdfWriter) setTextColor(r, g, b float64) {
	p.txR, p.txG, p.txB = r, g, b
}

func (p *pdfWriter) text(x, y float64, s string) {
	s = pdfSafeString(s)
	fn := fontAlias(p.curFont)
	ypt := pageYToPt(p.pageH, y)
	p.emit(fmt.Sprintf("BT /F%s %.1f Tf %.3f %.3f %.3f rg %.3f %.3f Td (%s) Tj ET\n",
		fn, mmToPt(p.curSize), p.txR, p.txG, p.txB, mmToPt(x), ypt, s))
}

func (p *pdfWriter) setY(y float64) {
	if y > p.pageH-p.margin-10 {
		p.addPage()
		p.y = p.margin + 10
	} else {
		p.y = y
	}
}

func (p *pdfWriter) hline(x, y, w float64) {
	ypt := pageYToPt(p.pageH, y)
	xpt := mmToPt(x)
	wpt := mmToPt(w)
	p.emit(fmt.Sprintf("%.3f w %.3f %.3f m %.3f %.3f l S\n", 0.5, xpt, ypt, xpt+wpt, ypt))
}

func (p *pdfWriter) colorRect(x, y, w, h, r, g, b float64) {
	xpt := mmToPt(x)
	ypt := pageYToPt(p.pageH, y+h)
	wpt := mmToPt(w)
	hpt := mmToPt(h)
	p.emit(fmt.Sprintf("%.3f %.3f %.3f rg %.3f %.3f %.3f %.3f re f 0 0 0 rg\n",
		r, g, b, xpt, ypt, wpt, hpt))
}

func (p *pdfWriter) sectionHeader(title string) {
	if p.y > p.pageH-p.margin-30 {
		p.addPage()
	}
	p.setY(p.y + 6)
	p.setFont("Helvetica-Bold", 13)
	p.setTextColor(0, 0, 0)
	p.text(p.margin, p.y, title)
	p.setY(p.y + 8)
	p.setFont("Helvetica", 10)
}

func (p *pdfWriter) body(s string) {
	p.setFont("Helvetica", 10)
	p.setTextColor(0, 0, 0)
	for _, line := range wrapText(s, 80) {
		if p.y > p.pageH-p.margin-8 {
			p.addPage()
		}
		p.text(p.margin, p.y, line)
		p.setY(p.y + 5.5)
	}
}

func (p *pdfWriter) bodyWarn(s string) {
	p.setFont("Helvetica-Bold", 10)
	p.setTextColor(0.80, 0.20, 0.10)
	p.text(p.margin, p.y, s)
	p.setTextColor(0, 0, 0)
	p.setFont("Helvetica", 10)
	p.setY(p.y + 6)
}

func (p *pdfWriter) table(rows [][]string, colWidths []float64) {
	if len(rows) == 0 {
		return
	}
	rowH := 6.5
	for ri, row := range rows {
		if p.y+rowH > p.pageH-p.margin-5 {
			p.addPage()
		}
		// Header row background
		if ri == 0 {
			totalW := 0.0
			for _, w := range colWidths {
				totalW += w
			}
			p.colorRect(p.margin, p.y, totalW, rowH, 0.90, 0.90, 0.90)
			p.setFont("Helvetica-Bold", 8)
		} else {
			p.setFont("Helvetica", 8)
		}
		p.setTextColor(0, 0, 0)
		x := p.margin
		for ci, cell := range row {
			if ci >= len(colWidths) {
				break
			}
			p.text(x+1, p.y+4.5, truncate(cell, int(colWidths[ci]/2.2)))
			x += colWidths[ci]
		}
		p.setY(p.y + rowH)
	}
	p.setY(p.y + 3)
}

func (p *pdfWriter) end() ([]byte, error) {
	// Build font dictionary (4 fonts: Helvetica, Helvetica-Bold, Courier, Courier-Bold).
	fonts := []struct{ alias, base string }{
		{"Hv", "Helvetica"},
		{"HvB", "Helvetica-Bold"},
		{"Cr", "Courier"},
		{"CrB", "Courier-Bold"},
	}
	fontObjNums := map[string]int{}
	for _, f := range fonts {
		body := fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", f.base)
		num := len(p.objs) + 1
		p.objs = append(p.objs, body)
		fontObjNums[f.alias] = num
	}

	// Build font dict string for page resources.
	var fontDictParts []string
	for _, f := range fonts {
		fontDictParts = append(fontDictParts, fmt.Sprintf("/F%s %d 0 R", f.alias, fontObjNums[f.alias]))
	}
	fontDictStr := strings.Join(fontDictParts, " ")

	// Build page and content-stream objects.
	pagesObjNum := 2
	pageObjNums := make([]int, len(p.streams))
	for i, stream := range p.streams {
		streamObjNum := len(p.objs) + 1
		streamBody := fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream)
		p.objs = append(p.objs, streamBody)

		pageObjNum := len(p.objs) + 1
		pageBody := fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.3f %.3f] /Resources << /Font << %s >> >> /Contents %d 0 R >>",
			pagesObjNum, mmToPt(p.pageW), mmToPt(p.pageH), fontDictStr, streamObjNum)
		p.objs = append(p.objs, pageBody)
		pageObjNums[i] = pageObjNum
	}

	// Build Kids list for Pages object.
	kids := make([]string, len(pageObjNums))
	for i, n := range pageObjNums {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	p.objs[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), len(pageObjNums))

	// Catalog.
	p.objs[0] = fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObjNum)

	// Write PDF to buffer.
	p.buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, len(p.objs))
	for i, body := range p.objs {
		offsets[i] = p.buf.Len()
		fmt.Fprintf(&p.buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}

	// Cross-reference table.
	xrefOffset := p.buf.Len()
	fmt.Fprintf(&p.buf, "xref\n0 %d\n", len(p.objs)+1)
	fmt.Fprintf(&p.buf, "%010d %05d f \n", 0, 65535)
	for _, off := range offsets {
		fmt.Fprintf(&p.buf, "%010d %05d n \n", off, 0)
	}

	// Trailer.
	fmt.Fprintf(&p.buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(p.objs)+1, xrefOffset)

	return p.buf.Bytes(), nil
}

// --- PDF unit conversion helpers (A4 at 72dpi: 1mm = 2.834645 pt) ---

const mmPerPt = 2.834645

func mmToPt(mm float64) float64 { return mm * mmPerPt }

// pageYToPt converts mm from top-of-page to PDF points from bottom-of-page.
func pageYToPt(pageHmm, ymm float64) float64 {
	return mmToPt(pageHmm - ymm)
}

func fontAlias(name string) string {
	switch name {
	case "Helvetica-Bold":
		return "HvB"
	case "Courier":
		return "Cr"
	case "Courier-Bold":
		return "CrB"
	default:
		return "Hv"
	}
}

// pdfSafeString escapes characters that are special in PDF string literals.
func pdfSafeString(s string) string {
	var sb strings.Builder
	for _, ch := range s {
		switch ch {
		case '(':
			sb.WriteString(`\(`)
		case ')':
			sb.WriteString(`\)`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			if ch > 127 {
				// Replace non-ASCII with '?'
				sb.WriteByte('?')
			} else {
				sb.WriteRune(ch)
			}
		}
	}
	return sb.String()
}

// wrapText splits text into lines of at most n characters, breaking on spaces.
func wrapText(s string, n int) []string {
	if len(s) <= n {
		return []string{s}
	}
	var lines []string
	for len(s) > n {
		cut := n
		if idx := strings.LastIndex(s[:n], " "); idx > 0 {
			cut = idx
		}
		lines = append(lines, s[:cut])
		s = strings.TrimLeft(s[cut:], " ")
	}
	if s != "" {
		lines = append(lines, s)
	}
	return lines
}

// truncate returns s truncated to at most n runes, with "…" appended if truncated.
func truncate(s string, n int) string {
	if n < 3 {
		n = 3
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "."
}
