import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from pathlib import Path
from scanner import scan_ports
from parsers.generic_json import GenericJSONParser
from analyzers.rules import analyze_rules

# Color Palette for Modern Dark Theme
BG_DARK = "#1e1e2e"
BG_CARD = "#2a2a3c"
FG_LIGHT = "#cdd6f4"
ACCENT_BLUE = "#89b4fa"
ACCENT_CRITICAL = "#f38ba8"
ACCENT_HIGH = "#fab387"
ACCENT_GREEN = "#a6e3a1"
BORDER_COLOR = "#45475a"


class FirewallSecurityAuditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Security Auditor V5.2 (Modern Dark)")
        self.root.geometry("1200x780")
        self.root.minsize(1000, 680)
        self.root.configure(bg=BG_DARK)

        self.rules = []
        self.findings = []
        self.scan_results = []

        self.build_style()
        self.build_ui()

    def build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Global Styles
        style.configure(".", background=BG_DARK, foreground=FG_LIGHT, font=("Segoe UI", 10))
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_CARD, foreground=FG_LIGHT, padding=[12, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT_BLUE)], foreground=[("selected", BG_DARK)])

        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), foreground=FG_LIGHT, background=BG_DARK)
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10, "italic"), foreground="#a6adc8", background=BG_DARK)
        style.configure("CardValue.TLabel", font=("Segoe UI", 18, "bold"), foreground=ACCENT_BLUE, background=BG_CARD)
        style.configure("CardTitle.TLabel", font=("Segoe UI", 9, "bold"), foreground="#bac2de", background=BG_CARD)
        
        # Buttons
        style.configure("TButton", font=("Segoe UI", 9, "bold"), background=BG_CARD, foreground=FG_LIGHT, borderwidth=1)
        style.map("TButton", background=[("active", ACCENT_BLUE)], foreground=[("active", BG_DARK)])

        # Entry fields dark mode fix
        style.configure("TEntry", fieldbackground=BG_CARD, foreground=FG_LIGHT, insertcolor=FG_LIGHT)

        # Treeview (Tables)
        style.configure("Treeview", background=BG_CARD, fieldbackground=BG_CARD, foreground=FG_LIGHT, rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#313244", foreground=FG_LIGHT, font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", ACCENT_BLUE)], foreground=[("selected", BG_DARK)])

    def build_ui(self):
        # Header Section
        header = ttk.Frame(self.root, padding=20)
        header.pack(fill="x")
        ttk.Label(header, text="🛡️ Firewall Security Auditor", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Network exposure + firewall policy analysis dashboard | V5.2",
            style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        # Metric Cards Section
        cards_frame = tk.Frame(self.root, bg=BG_DARK)
        cards_frame.pack(fill="x", padx=20, pady=5)
        
        self.rule_value = self.create_card(cards_frame, "RULES ANALYZED", "0")
        self.finding_value = self.create_card(cards_frame, "TOTAL FINDINGS", "0")
        self.critical_value = self.create_card(cards_frame, "CRITICAL RISKS", "0", ACCENT_CRITICAL)
        self.high_value = self.create_card(cards_frame, "HIGH RISKS", "0", ACCENT_HIGH)

        # Main Notebook Tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=15)

        self.network_tab = ttk.Frame(notebook, padding=15)
        self.firewall_tab = ttk.Frame(notebook, padding=15)
        self.report_tab = ttk.Frame(notebook, padding=15)

        notebook.add(self.network_tab, text="🌐 Network Audit")
        notebook.add(self.firewall_tab, text="🔒 Firewall Policy")
        notebook.add(self.report_tab, text="📄 Report Generation")

        self.build_network_tab()
        self.build_firewall_tab()
        self.build_report_tab()

        # Footer Warning
        footer = ttk.Frame(self.root, padding=(20, 5))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="⚠️ Use only on systems and configurations you own or are authorized to assess.",
            style="Subtitle.TLabel"
        ).pack(anchor="w")

    def create_card(self, parent, title, value, val_color=ACCENT_BLUE):
        card_container = tk.Frame(parent, bg=BORDER_COLOR, padx=1, pady=1)
        card_container.pack(side="left", fill="x", expand=True, padx=4)
        
        inner_frame = tk.Frame(card_container, bg=BG_CARD, padx=15, pady=12)
        inner_frame.pack(fill="both", expand=True)

        tk.Label(inner_frame, text=title, font=("Segoe UI", 9, "bold"), fg="#bac2de", bg=BG_CARD).pack(anchor="w")
        lbl = tk.Label(inner_frame, text=value, font=("Segoe UI", 18, "bold"), fg=val_color, bg=BG_CARD)
        lbl.pack(anchor="w", pady=(4, 0))
        return lbl

    def build_network_tab(self):
        controls = ttk.Frame(self.network_tab)
        controls.pack(fill="x", pady=(0, 12))

        ttk.Label(controls, text="Target IP:").pack(side="left")
        self.target_entry = ttk.Entry(controls, width=18, font=("Segoe UI", 10))
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", padx=8)

        ttk.Label(controls, text="Ports:").pack(side="left")
        self.ports_entry = ttk.Entry(controls, width=32, font=("Segoe UI", 10))
        self.ports_entry.insert(0, "22,23,80,443,3389,5985,5986,8080")
        self.ports_entry.pack(side="left", padx=8)

        self.scan_btn = ttk.Button(controls, text="RUN NETWORK AUDIT", command=self.start_network_audit)
        self.scan_btn.pack(side="left", padx=5)

        # Table Container
        table_frame = tk.Frame(self.network_tab, bg=BORDER_COLOR, padx=1, pady=1)
        table_frame.pack(fill="both", expand=True)

        columns = ("port", "status", "latency")
        self.network_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        for c, label, width in [
            ("port", "Port", 150),
            ("status", "Status", 180),
            ("latency", "Latency", 180),
        ]:
            self.network_table.heading(c, text=label)
            self.network_table.column(c, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.network_table.yview)
        self.network_table.configure(yscrollcommand=scrollbar.set)
        
        self.network_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def build_firewall_tab(self):
        controls = ttk.Frame(self.firewall_tab)
        controls.pack(fill="x", pady=(0, 12))

        ttk.Button(
            controls,
            text="📂 IMPORT FIREWALL JSON",
            command=self.import_firewall_json
        ).pack(side="left")

        ttk.Button(
            controls,
            text="⚡ LOAD SAMPLE POLICY",
            command=lambda: self.load_policy("samples/firewall_rules.json")
        ).pack(side="left", padx=8)

        self.policy_status = ttk.Label(controls, text="Status: No policy loaded", font=("Segoe UI", 9, "italic"))
        self.policy_status.pack(side="left", padx=10)

        # Table Container
        table_frame = tk.Frame(self.firewall_tab, bg=BORDER_COLOR, padx=1, pady=1)
        table_frame.pack(fill="both", expand=True)

        columns = ("severity", "rule", "title", "description", "recommendation")
        self.finding_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        widths = {
            "severity": 100,
            "rule": 80,
            "title": 220,
            "description": 380,
            "recommendation": 380,
        }
        for c in columns:
            self.finding_table.heading(c, text=c.upper())
            self.finding_table.column(c, width=widths[c], anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.finding_table.yview)
        self.finding_table.configure(yscrollcommand=scrollbar.set)

        self.finding_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def build_report_tab(self):
        top = ttk.Frame(self.report_tab)
        top.pack(fill="x", pady=(0, 10))
        ttk.Button(top, text="📝 GENERATE REPORT", command=self.generate_report).pack(side="left")
        ttk.Button(top, text="💾 SAVE REPORT", command=self.save_report).pack(side="left", padx=8)

        text_frame = tk.Frame(self.report_tab, bg=BORDER_COLOR, padx=1, pady=1)
        text_frame.pack(fill="both", expand=True)

        self.report_text = tk.Text(
            text_frame, wrap="word", font=("Consolas", 10),
            bg=BG_CARD, fg=FG_LIGHT, insertbackground=FG_LIGHT, borderwidth=0, highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=scrollbar.set)

        self.report_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def start_network_audit(self):
        target = self.target_entry.get().strip()
        try:
            ports = [int(x.strip()) for x in self.ports_entry.get().split(",") if x.strip()]
            if not ports or any(p < 1 or p > 65535 for p in ports):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid ports", "Use values such as 22,80,443,3389.")
            return

        self.scan_btn.config(state="disabled", text="SCANNING...")
        for item in self.network_table.get_children():
            self.network_table.delete(item)

        def worker():
            results = scan_ports(target, ports)
            self.root.after(0, lambda: self.finish_network_audit(results))

        threading.Thread(target=worker, daemon=True).start()

    def finish_network_audit(self, results):
        self.scan_results = results
        for result in results:
            self.network_table.insert(
                "", "end",
                values=(result["port"], result["status"], f'{result["latency"]:.1f} ms')
            )
        self.scan_btn.config(state="normal", text="RUN NETWORK AUDIT")

    def import_firewall_json(self):
        filename = filedialog.askopenfilename(
            title="Select firewall JSON export",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.load_policy(filename)

    def load_policy(self, filename):
        try:
            parser = GenericJSONParser()
            self.rules = parser.parse(filename)
            self.findings = analyze_rules(self.rules)
        except Exception as exc:
            messagebox.showerror("Policy import failed", str(exc))
            return

        for item in self.finding_table.get_children():
            self.finding_table.delete(item)

        for f in self.findings:
            self.finding_table.insert(
                "", "end",
                values=(
                    f.severity,
                    f.rule_id,
                    f.title,
                    f.description,
                    f.recommendation
                )
            )

        self.rule_value.config(text=str(len(self.rules)))
        self.finding_value.config(text=str(len(self.findings)))
        self.critical_value.config(text=str(sum(f.severity == "CRITICAL" for f in self.findings)))
        self.high_value.config(text=str(sum(f.severity == "HIGH" for f in self.findings)))
        self.policy_status.config(text=f"Status: Loaded ({Path(filename).name})")

    def generate_report(self):
        lines = [
            "FIREWALL SECURITY AUDITOR V5.2\n",
            "=" * 80 + "\n\n",
            f"Firewall rules analyzed: {len(self.rules)}\n",
            f"Policy findings: {len(self.findings)}\n",
            f"Network results: {len(self.scan_results)}\n\n",
        ]

        if self.findings:
            lines.append("POLICY FINDINGS\n")
            lines.append("-" * 80 + "\n")
            for f in self.findings:
                lines.extend([
                    f"[{f.severity}] Rule {f.rule_id}: {f.title}\n",
                    f"Description: {f.description}\n",
                    f"Recommendation: {f.recommendation}\n\n"
                ])

        if self.scan_results:
            lines.append("\nNETWORK AUDIT\n")
            lines.append("-" * 80 + "\n")
            for r in self.scan_results:
                lines.append(
                    f"TCP/{r['port']}: {r['status']} ({r['latency']:.1f} ms)\n"
                )

        self.report_text.delete("1.0", tk.END)
        self.report_text.insert("1.0", "".join(lines))

    def save_report(self):
        self.generate_report()
        filename = filedialog.asksaveasfilename(
            title="Save audit report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        if filename:
            Path(filename).write_text(
                self.report_text.get("1.0", tk.END),
                encoding="utf-8"
            )
            messagebox.showinfo("Success", "Report saved successfully!")


if __name__ == "__main__":
    root = tk.Tk()
    FirewallSecurityAuditor(root)
    root.mainloop()