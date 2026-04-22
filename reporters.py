import io
from typing import List, Any
from fpdf import FPDF
from datetime import datetime

class PhishGuardPDF(FPDF):
    def header(self):
        # Document Header
        self.set_font('Helvetica', 'B', 18)
        self.set_text_color(79, 70, 229) # Indigo 600
        self.cell(0, 10, 'PhishGuard Threat Intelligence', 0, 1, 'L')
        
        self.set_font('Helvetica', '', 11)
        self.set_text_color(100, 116, 139) # Slate 500
        self.cell(0, 5, 'Automated Phishing Domain Scan Report', 0, 1, 'L')
        self.ln(10)

    def footer(self):
        # Document Footer
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(148, 163, 184)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - Generated on {timestamp} UTC', 0, 0, 'C')

def generate_scan_pdf(session_domain: str, results: List[Any], session_id: str) -> bytes:
    """
    Generates a PDF byte string containing the summary and list of detected threats.
    `results` is a list of DetectedDomain objects.
    """
    pdf = PhishGuardPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # ── METRICS SECTION ──
    malicious = [d for d in results if d.risk_status == 'Malicious']
    suspicious = [d for d in results if d.risk_status == 'Suspicious']
    
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, f"Target Domain: {session_domain}", 0, 1, 'L')
    
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, f"Session ID: {session_id[:8]}", 0, 1, 'L')
    pdf.cell(0, 6, f"Total Domains Discovered: {len(results)}", 0, 1, 'L')
    
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(220, 38, 38)
    pdf.cell(0, 6, f"Malicious Found: {len(malicious)}", 0, 1, 'L')
    
    pdf.set_text_color(245, 158, 11)
    pdf.cell(0, 6, f"Suspicious Found: {len(suspicious)}", 0, 1, 'L')
    
    pdf.ln(10)
    
    # ── TABLE HEADER ──
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_fill_color(241, 245, 249) # Slate 100
    pdf.set_text_color(71, 85, 105) # Slate 600
    
    # Column widths (Total width in standard A4 portrait is ~190)
    w_dom, w_score, w_status, w_ip = 75, 25, 30, 60
    
    pdf.cell(w_dom, 10, 'Discovered Domain', 1, 0, 'C', True)
    pdf.cell(w_score, 10, 'Score', 1, 0, 'C', True)
    pdf.cell(w_status, 10, 'Status', 1, 0, 'C', True)
    pdf.cell(w_ip, 10, 'Resolved IP', 1, 1, 'C', True)
    
    # ── TABLE ROWS ──
    pdf.set_font('Helvetica', '', 9)
    
    # Sort malicious first, then suspicious, then by score
    sorted_results = sorted(results, key=lambda x: x.risk_score, reverse=True)
    
    for d in sorted_results:
        ed = d.enriched_data or {}
        ip_list = ed.get('dns_a') or []
        ip_str = ip_list[0] if ip_list else 'Unresolved'
        
        pdf.set_text_color(30, 41, 59)
        pdf.cell(w_dom, 8, d.domain[:35], 1, 0, 'L')
        
        # Color coding the score & status
        if d.risk_status == 'Malicious':
            pdf.set_text_color(220, 38, 38)
        elif d.risk_status == 'Suspicious':
            pdf.set_text_color(245, 158, 11)
        else:
            pdf.set_text_color(16, 185, 129) # Emerald 500
            
        pdf.cell(w_score, 8, str(d.risk_score), 1, 0, 'C')
        pdf.cell(w_status, 8, d.risk_status, 1, 0, 'C')
        
        pdf.set_text_color(100, 116, 139)
        pdf.cell(w_ip, 8, ip_str[:25], 1, 1, 'C')
        
    # output(dest="S") returns bytes in fpdf2
    return pdf.output()
