"""
Tkinter GUI application for building timestomp detection rules.
Allows users to create, edit, and delete rules for timestomp_rules.yaml file.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import tkinter.font as tkfont
import yaml
import os
from typing import Dict, List, Any, Optional
import sv_ttk
import re
from datetime import datetime

# Optional date picker support
try:
    from tkcalendar import DateEntry, Calendar  # type: ignore
    HAS_TKCALENDAR = True
except Exception:
    HAS_TKCALENDAR = False


class RuleBuilderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Timestomp X Rule Builder")
        self.root.iconbitmap("logo.ico")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)  # Set minimum window size
        
        self.rules_file = "timestomp_rules.yaml"
        self.rules_data = self.load_rules()
        self.selected_rule_index = None
        
        self.create_widgets()
        self.refresh_rule_list()
    
    def load_rules(self) -> Dict[str, Any]:
        """Load rules from YAML file."""
        if not os.path.exists(self.rules_file):
            return {"rules": []}
        
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data if data else {"rules": []}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load rules: {str(e)}")
            return {"rules": []}
    
    def save_rules(self):
        """Save rules to YAML file."""
        try:
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(self.rules_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            messagebox.showinfo("Success", "Rules saved successfully!")
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules: {str(e)}")
            return False
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Left panel: Rule list
        left_panel = ttk.Frame(main_frame)
        left_panel.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        ttk.Label(left_panel, text="Existing Rules", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        # Scrollable listbox for rules
        list_frame = ttk.Frame(left_panel)
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.rule_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, width=30, height=20)
        self.rule_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.rule_listbox.yview)
        
        self.rule_listbox.bind('<<ListboxSelect>>', self.on_rule_select)
        
        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)
        
        # Right panel: Rule editor
        right_panel = ttk.LabelFrame(main_frame, text="Rule Editor", padding="10")
        right_panel.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        
        # Rule ID
        ttk.Label(right_panel, text="Rule ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.rule_id_entry = ttk.Entry(right_panel, width=30)
        self.rule_id_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Rule Name
        ttk.Label(right_panel, text="Rule Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.rule_name_entry = ttk.Entry(right_panel, width=30)
        self.rule_name_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Severity
        ttk.Label(right_panel, text="Severity:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.severity_var = tk.StringVar(value="Low")
        severity_combo = ttk.Combobox(right_panel, textvariable=self.severity_var, 
                                     values=["Low", "Medium", "High"], state="readonly", width=27)
        severity_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Explanation
        ttk.Label(right_panel, text="Explanation:").grid(row=3, column=0, sticky=(tk.W, tk.N), pady=5)
        self.explanation_text = scrolledtext.ScrolledText(right_panel, width=30, height=5, wrap=tk.WORD)
        self.explanation_text.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))

        # Targets section
        targets_frame = ttk.LabelFrame(right_panel, text="Targets (one per line)", padding="5")
        targets_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5), padx=5)
        self.targets_text = scrolledtext.ScrolledText(targets_frame, width=30, height=1, wrap=tk.NONE)
        self.targets_text.pack(fill=tk.BOTH, expand=True)

        # Timeframe section
        timeframe_frame = ttk.LabelFrame(right_panel, text="Timeframe (optional)", padding="5")
        timeframe_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 10), padx=5)

        # Date entries
        ttk.Label(timeframe_frame, text="Start Date:").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Label(timeframe_frame, text="End Date:").grid(row=0, column=2, sticky=tk.W, pady=3)

        if HAS_TKCALENDAR:
            self.start_date_var = tk.StringVar()
            self.end_date_var = tk.StringVar()
            self.start_date_entry = DateEntry(timeframe_frame, textvariable=self.start_date_var, date_pattern='yyyy-mm-dd', width=12)
            self.end_date_entry = DateEntry(timeframe_frame, textvariable=self.end_date_var, date_pattern='yyyy-mm-dd', width=12)
        else:
            self.start_date_entry = ttk.Entry(timeframe_frame, width=14)
            self.end_date_entry = ttk.Entry(timeframe_frame, width=14)
        self.start_date_entry.grid(row=0, column=1, sticky=tk.W, padx=(5, 5))
        self.end_date_entry.grid(row=0, column=3, sticky=tk.W)

        # Date picker buttons (work even when DateEntry not available)
        def open_calendar(target: str):
            if not HAS_TKCALENDAR:
                messagebox.showinfo("Date Picker", "Install 'tkcalendar' to use the calendar picker.\nTry: pip install tkcalendar")
                return
            top = tk.Toplevel(self.root)
            top.title("Select Date")
            top.iconbitmap("logo.ico")
            cal = Calendar(top, date_pattern='yyyy-mm-dd')
            cal.pack(padx=10, pady=10)
            def set_date():
                date_str = cal.get_date()
                if target == 'start':
                    if HAS_TKCALENDAR and isinstance(self.start_date_entry, DateEntry):
                        self.start_date_var.set(date_str)
                    else:
                        self.start_date_entry.delete(0, tk.END)
                        self.start_date_entry.insert(0, date_str)
                else:
                    if HAS_TKCALENDAR and isinstance(self.end_date_entry, DateEntry):
                        self.end_date_var.set(date_str)
                    else:
                        self.end_date_entry.delete(0, tk.END)
                        self.end_date_entry.insert(0, date_str)
                top.destroy()
            ttk.Button(top, text="OK", command=set_date).pack(pady=(0,10))

        #ttk.Button(timeframe_frame, text="Pick", width=5, command=lambda: open_calendar('start')).grid(row=0, column=1, sticky=tk.E, padx=(124,0))
        #ttk.Button(timeframe_frame, text="Pick", width=5, command=lambda: open_calendar('end')).grid(row=0, column=3, sticky=tk.E, padx=(156,0))

        # Time entries
        ttk.Label(timeframe_frame, text="Start Time (HH:MM:SS):").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.start_time_entry = ttk.Entry(timeframe_frame, width=14)
        self.start_time_entry.insert(0, "00:00:00")
        self.start_time_entry.grid(row=1, column=1, sticky=tk.W, padx=(5, 15))

        ttk.Label(timeframe_frame, text="End Time (HH:MM:SS):").grid(row=1, column=2, sticky=tk.W, pady=3)
        self.end_time_entry = ttk.Entry(timeframe_frame, width=14)
        self.end_time_entry.insert(0, "23:59:59")
        self.end_time_entry.grid(row=1, column=3, sticky=tk.W)

        # Only date checkbox
        self.only_date_var = tk.BooleanVar(value=False)
        def on_only_date_toggle():
            if self.only_date_var.get():
                self.start_time_entry.delete(0, tk.END)
                self.start_time_entry.insert(0, "00:00:00")
                self.end_time_entry.delete(0, tk.END)
                self.end_time_entry.insert(0, "23:59:59")
                self.start_time_entry.config(state="disabled")
                self.end_time_entry.config(state="disabled")
            else:
                self.start_time_entry.config(state="normal")
                self.end_time_entry.config(state="normal")
        only_date_cb = ttk.Checkbutton(timeframe_frame, text="Only specify date (auto-time)", variable=self.only_date_var, command=on_only_date_toggle)
        only_date_cb.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(8, 0))
        
        # Logic type
        ttk.Label(right_panel, text="Logic Type:").grid(row=6, column=0, sticky=tk.W, pady=5)
        logic_frame = ttk.Frame(right_panel)
        logic_frame.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        self.logic_var = tk.StringVar(value="any_of")
        ttk.Radiobutton(logic_frame, text="any_of", variable=self.logic_var, 
                       value="any_of").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(logic_frame, text="all_of", variable=self.logic_var, 
                       value="all_of").pack(side=tk.LEFT, padx=5)
        
        # Conditions section
        conditions_label_frame = ttk.LabelFrame(right_panel, text="Conditions", padding="5")
        conditions_label_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), 
                                   pady=10, padx=5)
        
        # Create a container frame for the scrollable area
        conditions_container = ttk.Frame(conditions_label_frame)
        conditions_container.pack(fill=tk.BOTH, expand=True, before=None)
        
        # Scrollable frame for conditions - increased initial height and made resizable
        conditions_canvas = tk.Canvas(conditions_container, height=250)
        conditions_scrollbar = ttk.Scrollbar(conditions_container, orient="vertical", 
                                             command=conditions_canvas.yview)
        self.conditions_frame = ttk.Frame(conditions_canvas)
        
        self.conditions_frame.bind(
            "<Configure>",
            lambda e: conditions_canvas.configure(scrollregion=conditions_canvas.bbox("all"))
        )
        
        self.conditions_canvas_window = conditions_canvas.create_window((0, 0), window=self.conditions_frame, anchor="nw")
        conditions_canvas.configure(yscrollcommand=conditions_scrollbar.set)
        
        # Make the inner frame width match the canvas width
        def configure_canvas_width(event):
            canvas_width = event.width
            conditions_canvas.itemconfig(self.conditions_canvas_window, width=canvas_width)
        
        conditions_canvas.bind('<Configure>', configure_canvas_width)
        
        conditions_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conditions_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.condition_entries = []
        
        # Add/Remove condition buttons
        condition_buttons_frame = ttk.Frame(conditions_label_frame)
        # Keep buttons visible even when the scrollable area shrinks
        condition_buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        
        ttk.Button(condition_buttons_frame, text="Add Condition", 
                  command=self.add_condition).pack(side=tk.LEFT, padx=5)
        ttk.Button(condition_buttons_frame, text="Custom Rule Builder", 
                  command=self.open_custom_rule_builder).pack(side=tk.LEFT, padx=5)
        ttk.Button(condition_buttons_frame, text="Remove Last", 
                  command=self.remove_last_condition).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        buttons_frame = ttk.Frame(right_panel)
        buttons_frame.grid(row=8, column=0, columnspan=2, pady=15)
        
        ttk.Button(buttons_frame, text="Save Rule", command=self.save_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Export YAML Preview", 
                  command=self.export_yaml_preview).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="New Rule", command=self.new_rule).pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        right_panel.columnconfigure(1, weight=1)
        right_panel.rowconfigure(7, weight=1)  # Conditions section row
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)
    
    def add_condition(self):
        """Add a new condition entry field."""
        condition_frame = ttk.Frame(self.conditions_frame)
        condition_frame.pack(fill=tk.X, pady=2, padx=5)
        
        entry = ttk.Entry(condition_frame, width=50)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        remove_btn = ttk.Button(condition_frame, text="×", width=3, 
                               command=lambda: self.remove_condition(condition_frame))
        remove_btn.pack(side=tk.RIGHT)
        
        self.condition_entries.append((condition_frame, entry))
    
    def remove_condition(self, condition_frame):
        """Remove a specific condition entry."""
        for i, (frame, entry) in enumerate(self.condition_entries):
            if frame == condition_frame:
                frame.destroy()
                self.condition_entries.pop(i)
                break
    
    def remove_last_condition(self):
        """Remove the last condition entry."""
        if self.condition_entries:
            frame, entry = self.condition_entries.pop()
            frame.destroy()
    
    def refresh_rule_list(self):
        """Refresh the rule listbox with current rules."""
        self.rule_listbox.delete(0, tk.END)
        rules = self.rules_data.get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "Unknown")
            rule_name = rule.get("name", "Unnamed")
            self.rule_listbox.insert(tk.END, f"{rule_id}: {rule_name}")
    
    def on_rule_select(self, event):
        """Handle rule selection from listbox."""
        selection = self.rule_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        rules = self.rules_data.get("rules", [])
        if index >= len(rules):
            return
        
        self.selected_rule_index = index
        rule = rules[index]
        
        # Populate form fields
        self.rule_id_entry.delete(0, tk.END)
        self.rule_id_entry.insert(0, rule.get("id", ""))
        
        self.rule_name_entry.delete(0, tk.END)
        self.rule_name_entry.insert(0, rule.get("name", ""))
        
        self.severity_var.set(rule.get("severity", "Low"))
        
        self.explanation_text.delete("1.0", tk.END)
        self.explanation_text.insert("1.0", rule.get("explanation", ""))

        # Populate targets
        self.targets_text.delete("1.0", tk.END)
        targets_list = rule.get("targets", []) or []
        if isinstance(targets_list, list):
            self.targets_text.insert("1.0", "\n".join(str(t) for t in targets_list))

        # Populate timeframe (best-effort parse)
        self.only_date_var.set(False)
        def set_time_entries_enabled(enabled: bool):
            state = "normal" if enabled else "disabled"
            self.start_time_entry.config(state=state)
            self.end_time_entry.config(state=state)
        # Reset entries
        if HAS_TKCALENDAR:
            self.start_date_var.set("")
            self.end_date_var.set("")
        else:
            self.start_date_entry.delete(0, tk.END)
            self.end_date_entry.delete(0, tk.END)
        self.start_time_entry.config(state="normal")
        self.end_time_entry.config(state="normal")
        self.start_time_entry.delete(0, tk.END)
        self.end_time_entry.delete(0, tk.END)
        self.start_time_entry.insert(0, "00:00:00")
        self.end_time_entry.insert(0, "23:59:59")

        timeframe_str = rule.get("timeframe")
        if isinstance(timeframe_str, str):
            both_re = re.compile(r"^\s*>=\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))?\s+and\s+<=\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))?\s*$")
            ge_re = re.compile(r"^\s*>=\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))?\s*$")
            le_re = re.compile(r"^\s*<=\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))?\s*$")
            m = both_re.match(timeframe_str) or ge_re.match(timeframe_str) or le_re.match(timeframe_str)
            if m:
                groups = m.groups()
                # Depending on which regex matched, groups may be (sdate, stime, edate, etime) or shorter
                try:
                    if len(groups) >= 1 and groups[0]:
                        if HAS_TKCALENDAR:
                            self.start_date_var.set(groups[0])
                        else:
                            self.start_date_entry.delete(0, tk.END)
                            self.start_date_entry.insert(0, groups[0])
                    if len(groups) >= 2 and groups[1]:
                        self.start_time_entry.delete(0, tk.END)
                        self.start_time_entry.insert(0, groups[1])
                    if len(groups) >= 3 and groups[2]:
                        if HAS_TKCALENDAR:
                            self.end_date_var.set(groups[2])
                        else:
                            self.end_date_entry.delete(0, tk.END)
                            self.end_date_entry.insert(0, groups[2])
                    if len(groups) >= 4 and groups[3]:
                        self.end_time_entry.delete(0, tk.END)
                        self.end_time_entry.insert(0, groups[3])
                    # If no times captured, enable only-date mode
                    no_times = (len(groups) < 2 or not groups[1]) and (len(groups) < 4 or not groups[3])
                    if no_times:
                        self.only_date_var.set(True)
                        set_time_entries_enabled(False)
                except Exception:
                    pass
        
        # Set logic type
        logic = rule.get("logic", {})
        if "any_of" in logic:
            self.logic_var.set("any_of")
        elif "all_of" in logic:
            self.logic_var.set("all_of")
        else:
            self.logic_var.set("any_of")
        
        # Clear and populate conditions
        for frame, entry in self.condition_entries:
            frame.destroy()
        self.condition_entries.clear()
        
        conditions = []
        if "any_of" in logic:
            conditions = logic.get("any_of", [])
        elif "all_of" in logic:
            conditions = logic.get("all_of", [])
        
        for condition_obj in conditions:
            condition_str = condition_obj.get("condition", "")
            self.add_condition()
            self.condition_entries[-1][1].insert(0, condition_str)
        
        # Add at least one empty condition if none exist
        if not self.condition_entries:
            self.add_condition()
    
    def validate_rule(self) -> Optional[Dict[str, Any]]:
        """Validate and create rule dictionary from form data."""
        rule_id = self.rule_id_entry.get().strip()
        rule_name = self.rule_name_entry.get().strip()
        explanation = self.explanation_text.get("1.0", tk.END).strip()
        logic_type = self.logic_var.get()
        
        if not rule_id:
            messagebox.showerror("Validation Error", "Rule ID is required!")
            return None
        
        if not rule_name:
            messagebox.showerror("Validation Error", "Rule Name is required!")
            return None
        
        if not explanation:
            messagebox.showerror("Validation Error", "Explanation is required!")
            return None
        
        # Collect conditions
        conditions = []
        for frame, entry in self.condition_entries:
            condition_str = entry.get().strip()
            if condition_str:
                conditions.append({"condition": condition_str})
        
        if not conditions:
            messagebox.showerror("Validation Error", "At least one condition is required!")
            return None
        
        # Build rule structure
        rule = {
            "id": rule_id,
            "name": rule_name,
            "severity": self.severity_var.get(),
            "explanation": explanation,
            "logic": {
                logic_type: conditions
            }
        }

        # Targets: parse multiline input into list
        targets_raw = self.targets_text.get("1.0", tk.END)
        targets_list: List[str] = []
        for line in targets_raw.splitlines():
            value = line.strip()
            if value:
                targets_list.append(value)
        if targets_list:
            rule["targets"] = targets_list

        # Timeframe: optional
        def get_date_str(entry_widget) -> str:
            if HAS_TKCALENDAR:
                # DateEntry has get() returning str
                return entry_widget.get().strip()
            return entry_widget.get().strip()

        start_date = get_date_str(self.start_date_entry)
        end_date = get_date_str(self.end_date_entry)
        start_time = self.start_time_entry.get().strip() or "00:00:00"
        end_time = self.end_time_entry.get().strip() or "23:59:59"

        # If only date checkbox is checked, coerce times
        if self.only_date_var.get():
            start_time = "00:00:00"
            end_time = "23:59:59"

        # Validate formats if any date is provided
        date_provided = bool(start_date or end_date)
        if date_provided:
            date_fmt = "%Y-%m-%d"
            time_fmt = "%H:%M:%S"
            def valid_date(s: str) -> bool:
                try:
                    datetime.strptime(s, date_fmt)
                    return True
                except Exception:
                    return False
            def valid_time(s: str) -> bool:
                try:
                    datetime.strptime(s, time_fmt)
                    return True
                except Exception:
                    return False
            if start_date and not valid_date(start_date):
                messagebox.showerror("Validation Error", "Start Date must be in YYYY-MM-DD format.")
                return None
            if end_date and not valid_date(end_date):
                messagebox.showerror("Validation Error", "End Date must be in YYYY-MM-DD format.")
                return None
            # Time validation only if time entries enabled or provided
            if start_date and not self.only_date_var.get() and start_time and not valid_time(start_time):
                messagebox.showerror("Validation Error", "Start Time must be in HH:MM:SS format.")
                return None
            if end_date and not self.only_date_var.get() and end_time and not valid_time(end_time):
                messagebox.showerror("Validation Error", "End Time must be in HH:MM:SS format.")
                return None
            # Ordering validation when both dates present
            if start_date and end_date:
                start_dt = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M:%S")
                end_dt = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M:%S")
                if end_dt < start_dt:
                    messagebox.showerror("Validation Error", "End date/time cannot be earlier than start date/time.")
                    return None

            # Build timeframe string
            tf_parts: List[str] = []
            if start_date:
                if self.only_date_var.get():
                    tf_parts.append(f">= {start_date}")
                else:
                    tf_parts.append(f">= {start_date} {start_time}")
            if end_date:
                if self.only_date_var.get():
                    clause = f"<= {end_date}"
                else:
                    clause = f"<= {end_date} {end_time}"
                if tf_parts:
                    rule["timeframe"] = f"{tf_parts[0]} and {clause}"
                else:
                    rule["timeframe"] = clause
            else:
                if tf_parts:
                    rule["timeframe"] = tf_parts[0]
        
        return rule
    
    def save_rule(self):
        """Save the current rule to the rules data and file."""
        rule = self.validate_rule()
        if not rule:
            return
        
        rules = self.rules_data.get("rules", [])
        
        # Check if rule ID already exists (and it's not the currently selected rule)
        rule_id = rule["id"]
        for i, existing_rule in enumerate(rules):
            if existing_rule.get("id") == rule_id and i != self.selected_rule_index:
                messagebox.showerror("Validation Error", 
                                    f"Rule ID '{rule_id}' already exists!")
                return
        
        # Update existing rule or add new one
        if self.selected_rule_index is not None:
            # Update existing rule
            rules[self.selected_rule_index] = rule
        else:
            # Add new rule
            rules.append(rule)
            self.selected_rule_index = len(rules) - 1
        
        self.rules_data["rules"] = rules
        
        # Save to file
        if self.save_rules():
            self.refresh_rule_list()
            # Update listbox selection
            self.rule_listbox.selection_clear(0, tk.END)
            if self.selected_rule_index is not None:
                self.rule_listbox.selection_set(self.selected_rule_index)
                self.rule_listbox.see(self.selected_rule_index)
    
    def delete_rule(self):
        """Delete the currently selected rule."""
        if self.selected_rule_index is None:
            messagebox.showwarning("Warning", "Please select a rule to delete!")
            return
        
        rules = self.rules_data.get("rules", [])
        if self.selected_rule_index >= len(rules):
            return
        
        rule = rules[self.selected_rule_index]
        rule_name = rule.get("name", "Unknown")
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete rule '{rule_name}'?"):
            rules.pop(self.selected_rule_index)
            self.rules_data["rules"] = rules
            
            if self.save_rules():
                self.selected_rule_index = None
                self.clear_form()
                self.refresh_rule_list()
    
    def clear_form(self):
        """Clear all form fields."""
        self.rule_id_entry.delete(0, tk.END)
        self.rule_name_entry.delete(0, tk.END)
        self.severity_var.set("Low")
        self.explanation_text.delete("1.0", tk.END)
        self.logic_var.set("any_of")

        # Clear targets and timeframe
        self.targets_text.delete("1.0", tk.END)
        if HAS_TKCALENDAR:
            self.start_date_var.set("")
            self.end_date_var.set("")
        else:
            self.start_date_entry.delete(0, tk.END)
            self.end_date_entry.delete(0, tk.END)
        self.start_time_entry.config(state="normal")
        self.end_time_entry.config(state="normal")
        self.only_date_var.set(False)
        self.start_time_entry.delete(0, tk.END)
        self.end_time_entry.delete(0, tk.END)
        self.start_time_entry.insert(0, "00:00:00")
        self.end_time_entry.insert(0, "23:59:59")
        
        for frame, entry in self.condition_entries:
            frame.destroy()
        self.condition_entries.clear()
        
        # Add one empty condition
        self.add_condition()
    
    def new_rule(self):
        """Clear form for creating a new rule."""
        self.selected_rule_index = None
        self.rule_listbox.selection_clear(0, tk.END)
        self.clear_form()
    
    def export_yaml_preview(self):
        """Show YAML preview in a popup window."""
        rule = self.validate_rule()
        if not rule:
            return
        
        # Create full structure for preview
        preview_data = {"rules": [rule]}
        
        try:
            yaml_str = yaml.safe_dump(preview_data, default_flow_style=False, 
                                    sort_keys=False, allow_unicode=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate YAML: {str(e)}")
            return
        
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title("YAML Preview")
        popup.iconbitmap("logo.ico")
        popup.geometry("700x500")
        
        text_frame = ttk.Frame(popup, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(text_frame, wrap=tk.NONE, 
                                               font=("Consolas", 10))
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert("1.0", yaml_str)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)
    
    def open_custom_rule_builder(self):
        """Open the Custom Rule Builder modal window."""
        CustomRuleBuilder(self.root, self)


class CustomRuleBuilder:
    """Modal window for building rule conditions interactively."""
    
    def __init__(self, parent, main_gui):
        self.parent = parent
        self.main_gui = main_gui
        self.result = None
        
        # Create modal window
        self.modal = tk.Toplevel(parent)
        self.modal.title("Custom Rule Builder")
        self.modal.iconbitmap("logo.ico")
        self.modal.geometry("700x600")
        self.modal.resizable(True, True)
        
        # Center the window
        self.modal.transient(parent)
        self.modal.grab_set()
        
        # Make window modal
        self.modal.focus_set()
        
        # Close handling
        self.modal.protocol("WM_DELETE_WINDOW", self.cancel)
        
        # Available sources
        self.sources = ["$MFT", "PREFETCH", "AMCACHE", "PE_COFF", "$USN_JOURNAL", 
                       "USERASSIST_REGKEY", "PCA_LOG", "APPCOMPATCACHE"]
        self.macb_options = ["", "m", "a", "c", "b", "...b", ".a..", "..c.", "...d"]
        self.operators = ["<", "<=", ">", ">=", "==", "!="]
        # USN Journal reasons
        self.usn_reasons = [
            "USN_REASON_DATA_OVERWRITE",
            "USN_REASON_DATA_EXTEND",
            "USN_REASON_DATA_TRUNCATION",
            "USN_REASON_BASIC_INFO_CHANGE",
            "USN_REASON_FILE_CREATE",
            "USN_REASON_FILE_DELETE",
            "USN_REASON_CLOSE",
            "USN_REASON_RENAME_OLD_NAME",
            "USN_REASON_RENAME_NEW_NAME",
            "USN_REASON_SECURITY_CHANGE",
            "USN_REASON_STREAM_CHANGE",
            "USN_REASON_OBJECT_ID_CHANGE",
            "USN_REASON_HARD_LINK_CHANGE",
            "USN_REASON_REPARSE_POINT_CHANGE",
        ]
        
        # small font for dense checkbox lists
        self.small_font = tkfont.Font(size=9)

        self.create_widgets()
        self.update_preview()
        self.auto_resize()
        
        # Center window on screen
        self.modal.update_idletasks()
        x = (self.modal.winfo_screenwidth() // 2) - (self.modal.winfo_width() // 2)
        y = (self.modal.winfo_screenheight() // 2) - (self.modal.winfo_height() // 2)
        self.modal.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Create all widgets in the modal."""
        self.main_frame = ttk.Frame(self.modal, padding="15")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left Source
        row = 0
        ttk.Label(self.main_frame, text="Left Source:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.left_source_var = tk.StringVar(value="")
        self.left_source_combo = ttk.Combobox(self.main_frame, textvariable=self.left_source_var,
                                             values=self.sources, state="readonly", width=25)
        self.left_source_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.left_source_var.trace('w', lambda *args: (self.render_macb_ui("left"), self.update_preview(), self.auto_resize()))
        
        # Left MACB Filter
        row += 1
        ttk.Label(self.main_frame, text="Left MACB Filter (optional):").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.left_macb_container = ttk.Frame(self.main_frame)
        self.left_macb_container.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.left_macb_var = tk.StringVar(value="")
        self.left_mft_vars = {'m': tk.BooleanVar(value=False), 'a': tk.BooleanVar(value=False), 'c': tk.BooleanVar(value=False), 'b': tk.BooleanVar(value=False)}
        self.left_prefetch_var = tk.StringVar(value="")
        self.left_usn_mode = tk.StringVar(value="lax")
        self.left_usn_reason_vars = {reason: tk.BooleanVar(value=False) for reason in self.usn_reasons}
        self.render_macb_ui("left")
        
        # Operator
        row += 1
        ttk.Label(self.main_frame, text="Operator:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.operator_var = tk.StringVar(value="<")
        self.operator_combo = ttk.Combobox(self.main_frame, textvariable=self.operator_var,
                                          values=self.operators, state="readonly", width=25)
        self.operator_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.operator_var.trace('w', lambda *args: self.update_preview())
        
        # Right Source
        row += 1
        ttk.Label(self.main_frame, text="Right Source:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.right_source_var = tk.StringVar(value="")
        self.right_source_combo = ttk.Combobox(self.main_frame, textvariable=self.right_source_var,
                                              values=self.sources, state="readonly", width=25)
        self.right_source_combo.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.right_source_var.trace('w', lambda *args: (self.render_macb_ui("right"), self.update_preview(), self.auto_resize()))
        
        # Right MACB Filter
        row += 1
        ttk.Label(self.main_frame, text="Right MACB Filter (optional):").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.right_macb_container = ttk.Frame(self.main_frame)
        self.right_macb_container.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.right_macb_var = tk.StringVar(value="")
        self.right_mft_vars = {'m': tk.BooleanVar(value=False), 'a': tk.BooleanVar(value=False), 'c': tk.BooleanVar(value=False), 'b': tk.BooleanVar(value=False)}
        self.right_prefetch_var = tk.StringVar(value="")
        self.right_usn_mode = tk.StringVar(value="lax")
        self.right_usn_reason_vars = {reason: tk.BooleanVar(value=False) for reason in self.usn_reasons}
        self.render_macb_ui("right")
        
        # BOOT_SESSIONS Check
        row += 1
        self.boot_sessions_var = tk.BooleanVar(value=False)
        boot_check = ttk.Checkbutton(self.main_frame, text="Include AUTH_SESSIONS Check",
                                    variable=self.boot_sessions_var,
                                    command=self.on_boot_sessions_toggle)
        boot_check.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=10)
        self.boot_sessions_var.trace('w', lambda *args: self.update_preview())
        
        # Preview box
        row += 1
        ttk.Label(self.main_frame, text="Preview:").grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=(10, 5))
        self.preview_text = scrolledtext.ScrolledText(self.main_frame, height=6, width=50,
                                                      font=("Consolas", 10), wrap=tk.WORD,
                                                      state=tk.DISABLED)
        self.preview_text.grid(row=row+1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), 
                               pady=5)
        
        # Buttons
        row += 2
        buttons_frame = ttk.Frame(self.main_frame)
        buttons_frame.grid(row=row, column=0, columnspan=2, pady=15)
        
        ttk.Button(buttons_frame, text="Test Condition", 
                  command=self.test_condition).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Insert Condition", 
                  command=self.insert_condition).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Cancel", 
                  command=self.cancel).pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(row-1, weight=1)

    def auto_resize(self):
        try:
            self.modal.update_idletasks()
            req_w = self.main_frame.winfo_reqwidth() + 40
            req_h = self.main_frame.winfo_reqheight() + 40
            max_w = int(self.modal.winfo_screenwidth() * 0.9)
            max_h = int(self.modal.winfo_screenheight() * 0.9)
            w = min(req_w, max_w)
            h = min(req_h, max_h)
            self.modal.geometry(f"{w}x{h}")
        except Exception:
            pass
    
    def on_boot_sessions_toggle(self):
        """Handle BOOT_SESSIONS checkbox toggle."""
        if self.boot_sessions_var.get():
            # Disable right side
            self.right_source_combo.config(state="disabled")
            try:
                for child in self.right_macb_container.winfo_children():
                    child.config(state="disabled")
            except Exception:
                pass
            self.operator_combo.config(state="disabled")
        else:
            # Enable right side
            self.right_source_combo.config(state="readonly")
            try:
                for child in self.right_macb_container.winfo_children():
                    child.config(state="normal")
            except Exception:
                pass
            self.operator_combo.config(state="readonly")
        self.update_preview()

    def _clear_container(self, container: ttk.Frame):
        for w in container.winfo_children():
            w.destroy()

    def render_macb_ui(self, side: str):
        """Render MACB/USN widgets depending on selected source for given side."""
        container = self.left_macb_container if side == "left" else self.right_macb_container
        source_var = self.left_source_var if side == "left" else self.right_source_var
        macb_var = self.left_macb_var if side == "left" else self.right_macb_var
        mft_vars = self.left_mft_vars if side == "left" else self.right_mft_vars
        usn_mode = self.left_usn_mode if side == "left" else self.right_usn_mode
        usn_reason_vars = self.left_usn_reason_vars if side == "left" else self.right_usn_reason_vars

        self._clear_container(container)

        source = source_var.get()
        if source == "$MFT":
            chk_frame = ttk.Frame(container)
            chk_frame.pack(anchor=tk.W)
            for key, label in [('m','M'),('a','A'),('c','C'),('b','B')]:
                ttk.Checkbutton(chk_frame, text=label, variable=mft_vars[key], command=self.update_preview).pack(side=tk.LEFT, padx=2)
        elif source == "PREFETCH":
            # Radio buttons for firstrun/lastrun
            radio_frame = ttk.Frame(container)
            radio_frame.pack(anchor=tk.W)
            var = self.left_prefetch_var if side == "left" else self.right_prefetch_var
            ttk.Radiobutton(radio_frame, text="all", value="all", variable=var, command=lambda: (self.update_preview())).pack(side=tk.LEFT, padx=2)
            ttk.Radiobutton(radio_frame, text="firstrun", value="firstrun", variable=var, command=lambda: (self.update_preview())).pack(side=tk.LEFT, padx=8)
            ttk.Radiobutton(radio_frame, text="lastrun", value="lastrun", variable=var, command=lambda: (self.update_preview())).pack(side=tk.LEFT, padx=8)
        elif source == "$USN_JOURNAL":
            mode_frame = ttk.Frame(container)
            mode_frame.pack(anchor=tk.W, pady=(0,4))
            ttk.Label(mode_frame, text="mode:").pack(side=tk.LEFT)
            mode_combo = ttk.Combobox(mode_frame, textvariable=usn_mode, values=["lax","strict"], state="readonly", width=10)
            mode_combo.pack(side=tk.LEFT, padx=(5,0))
            mode_combo.bind("<<ComboboxSelected>>", lambda e: self.update_preview())

            list_frame = ttk.Frame(container)
            list_frame.pack(anchor=tk.W)
            col = 0
            row = 0
            for reason in self.usn_reasons:
                cb = ttk.Checkbutton(list_frame, text=reason, variable=usn_reason_vars[reason], command=self.update_preview)
                cb.grid(row=row, column=col, sticky=tk.W, padx=(0,10), pady=1)
                try:
                    cb.configure(font=self.small_font)
                except Exception:
                    pass
                if col == 0:
                    col = 1
                else:
                    col = 0
                    row += 1
        else:
            combo = ttk.Combobox(container, textvariable=macb_var, values=self.macb_options, width=25)
            combo.pack(anchor=tk.W)
            macb_var.trace('w', lambda *args: self.update_preview())
    
    def build_condition_string(self) -> str:
        """Build the condition string from current selections."""
        if self.boot_sessions_var.get():
            # BOOT_SESSIONS format
            left_source = self.left_source_var.get().strip()
            left_macb = self._build_macb_clause(side="left")
            
            if not left_source:
                return ""
            
            # Build left datetime() call
            if left_macb:
                left_str = f"datetime({left_source}{left_macb})"
            else:
                left_str = f"datetime({left_source})"
            
            return f"{left_str} not between (AUTH_SESSIONS)"
        else:
            # Regular comparison format
            left_source = self.left_source_var.get().strip()
            left_macb = self._build_macb_clause(side="left")
            operator = self.operator_var.get().strip()
            right_source = self.right_source_var.get().strip()
            right_macb = self._build_macb_clause(side="right")
            
            if not left_source or not operator or not right_source:
                return ""
            
            # Build left datetime() call
            if left_macb:
                left_str = f"datetime({left_source}{left_macb})"
            else:
                left_str = f"datetime({left_source})"
            
            # Build right datetime() call
            if right_macb:
                right_str = f"datetime({right_source}{right_macb})"
            else:
                right_str = f"datetime({right_source})"
            
            return f"{left_str} {operator} {right_str}"

    def _build_macb_clause(self, side: str) -> str:
        """Return parameter part for datetime():
        - for $MFT: ", macb='....'" using M/A/C/B checkboxes
        - for $USN_JOURNAL: ".REASON|REASON, mode=..." using checklist and mode
        - default: use simple macb from combobox
        """
        source = (self.left_source_var if side == "left" else self.right_source_var).get().strip()
        if source == "$MFT":
            vars_map = self.left_mft_vars if side == "left" else self.right_mft_vars
            selected = {k for k, v in vars_map.items() if v.get()}
            # Map checkbox combinations to semantic suffix names
            mapping = {
                frozenset(): None,
                frozenset({'b'}): 'creation',
                frozenset({'c'}): 'metachange',
                frozenset({'c','b'}): 'metachange_creation',
                frozenset({'a'}): 'accessed',
                frozenset({'a','b'}): 'accessed_creation',
                frozenset({'a','c'}): 'accessed_metachange',
                frozenset({'a','c','b'}): 'accessed_metachange_creation',
                frozenset({'m'}): 'modified',
                frozenset({'m','b'}): 'modified_creation',
                frozenset({'m','c'}): 'modified_metachange',
                frozenset({'m','c','b'}): 'modified_metachange_creation',
                frozenset({'m','a'}): 'modified_accessed',
                frozenset({'m','a','b'}): 'modified_accessed_creation',
                frozenset({'m','a','c'}): 'modified_accessed_metachange',
                frozenset({'m','a','c','b'}): 'modified_accessed_metachange_creation',
            }
            name = mapping.get(frozenset(selected))
            return f".{name}" if name else ""
        if source == "$USN_JOURNAL":
            reason_vars = self.left_usn_reason_vars if side == "left" else self.right_usn_reason_vars
            selected = [r for r, v in reason_vars.items() if v.get()]
            mode = (self.left_usn_mode if side == "left" else self.right_usn_mode).get()
            suffix = ''
            if selected:
                suffix += "." + "|".join(selected)
            if mode:
                suffix += f", mode={mode}"
            return suffix
        if source == "PREFETCH":
            value = (self.left_prefetch_var if side == "left" else self.right_prefetch_var).get().strip()
            if value in ("firstrun", "lastrun"):
                return f".{value}"
            # 'all' or empty -> no suffix
            return ""
        macb = (self.left_macb_var if side == "left" else self.right_macb_var).get().strip()
        return f", macb='{macb}'" if macb else ""
    
    def update_preview(self):
        """Update the preview text box."""
        condition_str = self.build_condition_string()
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        if condition_str:
            self.preview_text.insert("1.0", condition_str)
        else:
            self.preview_text.insert("1.0", "(Incomplete condition)")
        self.preview_text.config(state=tk.DISABLED)
    
    def validate(self) -> bool:
        """Validate the condition inputs."""
        if self.boot_sessions_var.get():
            # Only need left source
            if not self.left_source_var.get():
                messagebox.showerror("Validation Error", 
                                    "Left Source is required when using BOOT_SESSIONS check!")
                return False
        else:
            # Need left source, operator, and right source
            if not self.left_source_var.get():
                messagebox.showerror("Validation Error", "Left Source is required!")
                return False
            if not self.operator_var.get():
                messagebox.showerror("Validation Error", "Operator is required!")
                return False
            if not self.right_source_var.get():
                messagebox.showerror("Validation Error", "Right Source is required!")
                return False
        
        return True
    
    def test_condition(self):
        """Show a popup with the current condition string."""
        condition_str = self.build_condition_string()
        if condition_str:
            messagebox.showinfo("Condition Test", f"Condition String:\n\n{condition_str}")
        else:
            messagebox.showwarning("Condition Test", "Please complete the condition first.")
    
    def insert_condition(self):
        """Insert the condition into the main GUI."""
        if not self.validate():
            return
        
        condition_str = self.build_condition_string()
        if not condition_str:
            messagebox.showerror("Error", "Could not generate condition string!")
            return
        
        # Add condition to main GUI
        self.main_gui.add_condition()
        # Set the text in the last added condition entry
        if self.main_gui.condition_entries:
            entry = self.main_gui.condition_entries[-1][1]
            entry.delete(0, tk.END)
            entry.insert(0, condition_str)
        
        # Show confirmation
        messagebox.showinfo("Success", f"Condition inserted:\n{condition_str}")
        
        # Close modal
        self.cancel()
    
    def cancel(self):
        """Close the modal without saving."""
        self.modal.destroy()


def main():
    """Main entry point for the application."""
    root = tk.Tk()
    sv_ttk.set_theme("light")
    app = RuleBuilderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

