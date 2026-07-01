# ──────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
# Title 			: SBOM Parser
# Conceptualized by : Dipta Roy
# Released On 		: 01-July-2026
# Usage 			: python SBOM_Parser_GUI.py
# ──────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────

import json
import csv
import os
import sys
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET


# ──────────────────────────────────────────────────────────────────────────────
# PARSING LOGIC
# ──────────────────────────────────────────────────────────────────────────────

def clean_supplier(raw: str) -> str:
    """Strip SPDX supplier-type prefixes: 'Organization:', 'Person:', 'Tool:'."""
    if not raw or raw == 'N/A':
        return raw
    for prefix in ('Organization:', 'Person:', 'Tool:'):
        if raw.startswith(prefix):
            return raw[len(prefix):].strip()
    return raw.strip()


def extract_package_manager_locator(external_refs):
    locators = []
    for ref in external_refs:
        category = ref.get('referenceCategory', '').upper().replace('_', '-')
        if category == 'PACKAGE-MANAGER':
            locator = ref.get('referenceLocator', 'N/A')
            locators.append(locator)
    return '; '.join(locators) if locators else 'N/A'


def parse_spdx_json(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)

    components = []
    for package in sbom_data.get('packages', []):
        components.append({
            'SPDX_ID'                 : package.get('SPDXID', 'N/A'),
            'Name'                    : package.get('name', 'N/A'),
            'Version'                 : package.get('versionInfo', 'N/A'),
            'Supplier'                : clean_supplier(            # ← cleaned
                                            package.get('supplier', 'N/A')),
            'License_Declared'        : package.get('licenseDeclared', 'N/A'),
            'Copyright_Text'          : package.get('copyrightText', 'N/A'),
            'Download_Location'       : package.get('downloadLocation', 'N/A'),
            'Homepage'                : package.get('homepage', 'N/A'),
            'Description'             : package.get('description', 'N/A'),
            'Package_Manager_Locator' : extract_package_manager_locator(
                                            package.get('externalRefs', []))
        })
    
    forward_rels = ('DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'HAS_PREREQUISITE', 'DESCRIBES', 'PACKAGE_OF')
    reverse_rels = ('DEPENDENCY_OF', 'CONTAINED_BY', 'PREREQUISITE_FOR', 'DESCRIBED_BY')
    relationships = []
    for rel in sbom_data.get('relationships', []):
        rel_type = rel.get('relationshipType', '')
        if rel_type in forward_rels:
            relationships.append({
                'parent': rel.get('spdxElementId'),
                'child': rel.get('relatedSpdxElement'),
                'type': rel_type
            })
        elif rel_type in reverse_rels:
            relationships.append({
                'parent': rel.get('relatedSpdxElement'),
                'child': rel.get('spdxElementId'),
                'type': rel_type
            })

    return components, relationships


def parse_spdx_tv(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    components       = []
    current_package  = None
    current_ext_refs = []
    relationships    = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if line.startswith('Relationship:'):
            parts = line.split(':', 1)[1].strip().split()
            if len(parts) >= 3:
                rel_type = parts[1]
                forward_rels = ('DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'HAS_PREREQUISITE', 'DESCRIBES', 'PACKAGE_OF')
                reverse_rels = ('DEPENDENCY_OF', 'CONTAINED_BY', 'PREREQUISITE_FOR', 'DESCRIBED_BY')
                if rel_type in forward_rels:
                    relationships.append({
                        'parent': parts[0],
                        'child': parts[2],
                        'type': rel_type
                    })
                elif rel_type in reverse_rels:
                    relationships.append({
                        'parent': parts[2],
                        'child': parts[0],
                        'type': rel_type
                    })
            continue

        if line.startswith('PackageName:'):
            if current_package is not None:
                current_package['Package_Manager_Locator'] = \
                    extract_package_manager_locator(current_ext_refs)
                components.append(current_package)
            current_package = {
                'SPDX_ID'                 : 'N/A',
                'Name'                    : line.split(':', 1)[1].strip(),
                'Version'                 : 'N/A',
                'Supplier'                : 'N/A',
                'License_Declared'        : 'N/A',
                'Copyright_Text'          : 'N/A',
                'Download_Location'       : 'N/A',
                'Homepage'                : 'N/A',
                'Description'             : 'N/A',
                'Package_Manager_Locator' : 'N/A'
            }
            current_ext_refs = []

        elif current_package is not None:
            tag_map = {
                'SPDXID:'                  : 'SPDX_ID',
                'PackageVersion:'          : 'Version',
                'PackageSupplier:'         : 'Supplier',
                'PackageLicenseDeclared:'  : 'License_Declared',
                'PackageCopyrightText:'    : 'Copyright_Text',
                'PackageDownloadLocation:' : 'Download_Location',
                'PackageHomePage:'         : 'Homepage',
                'PackageDescription:'      : 'Description',
            }
            for tag, key in tag_map.items():
                if line.startswith(tag):
                    value = line.split(':', 1)[1].strip()
                    if key == 'Supplier':          # ← cleaned
                        value = clean_supplier(value)
                    current_package[key] = value
                    break

            if line.startswith('ExternalRef:'):
                parts = line.split(':', 1)[1].strip().split()
                if len(parts) >= 3:
                    current_ext_refs.append({
                        'referenceCategory' : parts[0],
                        'referenceType'     : parts[1],
                        'referenceLocator'  : parts[2]
                    })

    if current_package is not None:
        current_package['Package_Manager_Locator'] = \
            extract_package_manager_locator(current_ext_refs)
        components.append(current_package)

    return components, relationships


def parse_spdx_xml(input_file):
    tree = ET.parse(input_file)
    root = tree.getroot()
    ns   = root.tag.split('}')[0] + '}' if root.tag.startswith('{') else ''

    components = []
    for package in root.findall(f'{ns}packages') or root.findall(f'{ns}package'):
        def get_text(tag):
            el = package.find(f'{ns}{tag}')
            return el.text.strip() if el is not None and el.text else 'N/A'

        ext_refs = []
        for ref in (package.findall(f'{ns}externalRefs') or
                    package.findall(f'{ns}externalRef')):
            cat = ref.find(f'{ns}referenceCategory')
            loc = ref.find(f'{ns}referenceLocator')
            ext_refs.append({
                'referenceCategory' : cat.text.strip() if cat is not None else '',
                'referenceLocator'  : loc.text.strip() if loc is not None else ''
            })

        components.append({
            'SPDX_ID'                 : get_text('SPDXID'),
            'Name'                    : get_text('name'),
            'Version'                 : get_text('versionInfo'),
            'Supplier'                : clean_supplier(            # ← cleaned
                                            get_text('supplier')),
            'License_Declared'        : get_text('licenseDeclared'),
            'Copyright_Text'          : get_text('copyrightText'),
            'Download_Location'       : get_text('downloadLocation'),
            'Homepage'                : get_text('homepage'),
            'Description'             : get_text('description'),
            'Package_Manager_Locator' : extract_package_manager_locator(ext_refs)
        })

    forward_rels = ('DEPENDS_ON', 'CONTAINS', 'DYNAMIC_LINK', 'STATIC_LINK', 'HAS_PREREQUISITE', 'DESCRIBES', 'PACKAGE_OF')
    reverse_rels = ('DEPENDENCY_OF', 'CONTAINED_BY', 'PREREQUISITE_FOR', 'DESCRIBED_BY')
    relationships = []
    for rel in root.iter(f'{ns}relationship'):
        r_type = rel.find(f'{ns}relationshipType')
        parent = rel.find(f'{ns}spdxElementId')
        child = rel.find(f'{ns}relatedSpdxElement')
        if r_type is not None and parent is not None and child is not None:
            rtype_text = r_type.text.strip()
            if rtype_text in forward_rels:
                relationships.append({
                    'parent': parent.text.strip(),
                    'child': child.text.strip(),
                    'type': rtype_text
                })
            elif rtype_text in reverse_rels:
                relationships.append({
                    'parent': child.text.strip(),
                    'child': parent.text.strip(),
                    'type': rtype_text
                })

    return components, relationships


def parse_cyclonedx_json(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)

    components = []
    for comp in sbom_data.get('components', []):
        license_decl = 'N/A'
        licenses = comp.get('licenses', [])
        if licenses:
            lic = licenses[0].get('license', {})
            license_decl = lic.get('id') or lic.get('name') or 'N/A'

        purl = comp.get('purl', 'N/A')
        supplier = 'N/A'
        sup_dict = comp.get('supplier')
        if sup_dict and isinstance(sup_dict, dict):
            supplier = sup_dict.get('name', 'N/A')

        components.append({
            'SPDX_ID'                 : comp.get('bom-ref', 'N/A'),
            'Name'                    : comp.get('name', 'N/A'),
            'Version'                 : comp.get('version', 'N/A'),
            'Supplier'                : clean_supplier(supplier),
            'License_Declared'        : license_decl,
            'Copyright_Text'          : 'N/A',
            'Download_Location'       : 'N/A',
            'Homepage'                : 'N/A',
            'Description'             : comp.get('description', 'N/A'),
            'Package_Manager_Locator' : purl
        })

    relationships = []
    for dep in sbom_data.get('dependencies', []):
        parent_ref = dep.get('ref')
        for child_ref in dep.get('dependsOn', []):
            relationships.append({
                'parent': parent_ref,
                'child': child_ref,
                'type': 'DEPENDS_ON'
            })

    return components, relationships


def parse_sbom(input_file):
    ext = os.path.splitext(input_file)[1].lower()
    if ext == '.json':
        with open(input_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception:
                data = {}
        if data.get('bomFormat') == 'CycloneDX':
            return parse_cyclonedx_json(input_file)
        return parse_spdx_json(input_file)
    elif ext in ['.spdx', '.tv']:
        return parse_spdx_tv(input_file)
    elif ext == '.xml':
        return parse_spdx_xml(input_file)
    else:
        raise ValueError(f"Unsupported format: {ext}")


def save_to_csv(components, output_file):
    fieldnames = [
        'Tree_ID', 'SPDX_ID', 'Name', 'Version', 'Supplier',
        'License_Declared', 'Copyright_Text', 'Download_Location',
        'Homepage', 'Description', 'Package_Manager_Locator'
    ]
    formatted_components = []
    for comp in components:
        row = comp.copy()
        if 'depth' in row and row['depth'] > 0:
            prefix = "    " * row['depth']
            row['Name'] = prefix + str(row.get('Name', ''))
        formatted_components.append(row)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(formatted_components)


# ──────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE & FONTS
# ──────────────────────────────────────────────────────────────────────────────

COLORS = {
    'bg'            : '#1E1E2E',
    'surface'       : '#2A2A3E',
    'surface2'      : '#313145',
    'primary'       : '#007bff',
    'primary_hover' : '#6A58E0',
    'secondary'     : '#FFFFFF',
    'success'       : '#28a745',
    'warning'       : '#ffc107',
    'error'         : '#dc3545',
    'text'          : '#E0E0F0',
    'text_dim'      : '#FFFFFF',
    'border'        : '#3D3D5C',
    'row_odd'       : '#252538',
    'row_even'      : '#2A2A3E',
    'header_bg'     : '#3A3A5C',
}

FONTS = {
    'title'   : ('Segoe UI', 18, 'bold'),
    'heading' : ('Segoe UI', 11, 'bold'),
    'body'    : ('Segoe UI', 10),
    'small'   : ('Segoe UI', 9),
    'mono'    : ('Consolas', 9),
    'button'  : ('Segoe UI', 10, 'bold'),
}

COLUMNS = (
    'Tree_ID', 'SPDX_ID', 'Name', 'Version', 'Supplier',
    'License_Declared', 'Copyright_Text',
    'Download_Location', 'Homepage',
    'Description', 'Package_Manager_Locator'
)

COL_WIDTHS = {
    'Tree_ID'                 : 80,
    'SPDX_ID'                 : 120,
    'Name'                    : 130,
    'Version'                 : 70,
    'Supplier'                : 140,
    'License_Declared'        : 110,
    'Copyright_Text'          : 130,
    'Download_Location'       : 140,
    'Homepage'                : 110,
    'Description'             : 130,
    'Package_Manager_Locator' : 180,
}


# ──────────────────────────────────────────────────────────────────────────────
# CUSTOM WIDGETS
# ──────────────────────────────────────────────────────────────────────────────

class RoundedButton(tk.Canvas):
    """Modern rounded-corner button."""

    def __init__(self, parent, text, command=None,
                 width=160, height=38,
                 bg=COLORS['primary'],
                 hover=COLORS['primary_hover'],
                 fg=COLORS['text'],
                 font=FONTS['button'],
                 radius=10, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=parent['bg'], highlightthickness=0, **kwargs)
        self._bg      = bg
        self._hover   = hover
        self._fg      = fg
        self._font    = font
        self._radius  = radius
        self._text    = text
        self._command = command
        self._width   = width
        self._height  = height
        self._enabled = True
        self._draw(self._bg)
        self.bind('<Enter>',           self._on_enter)
        self.bind('<Leave>',           self._on_leave)
        self.bind('<Button-1>',        self._on_click)
        self.bind('<ButtonRelease-1>', self._on_release)

    def _draw(self, colour):
        self.delete('all')
        r, w, h = self._radius, self._width, self._height
        for x1, y1, x2, y2, start in [
            (0,     0,     2*r,   2*r,   90),
            (w-2*r, 0,     w,     2*r,   0),
            (0,     h-2*r, 2*r,   h,     180),
            (w-2*r, h-2*r, w,     h,     270),
        ]:
            self.create_arc(x1, y1, x2, y2, start=start, extent=90,
                            fill=colour, outline=colour)
        self.create_rectangle(r, 0,   w-r, h,   fill=colour, outline=colour)
        self.create_rectangle(0, r,   w,   h-r, fill=colour, outline=colour)
        self.create_text(w // 2, h // 2, text=self._text,
                         fill=self._fg, font=self._font)

    def _on_enter(self, _):
        if self._enabled:
            self._draw(self._hover)

    def _on_leave(self, _):
        if self._enabled:
            self._draw(self._bg)

    def _on_click(self, _):
        if self._enabled:
            self._draw(self._bg)

    def _on_release(self, _):
        if self._enabled:
            self._draw(self._hover)
            if self._command:
                self._command()

    def set_text(self, text):
        self._text = text
        self._draw(self._bg)

    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self._draw(self._bg if enabled else COLORS['border'])


class StatCard(tk.Frame):
    """Small statistic card with label and value."""

    def __init__(self, parent, label, value='0',
                 accent=COLORS['primary'], **kwargs):
        super().__init__(parent,
                         bg=COLORS['surface2'],
                         highlightbackground=accent,
                         highlightthickness=2,
                         **kwargs)
        self._val_var = tk.StringVar(value=str(value))
        tk.Label(self, text=label,
                 bg=COLORS['surface2'], fg=COLORS['text_dim'],
                 font=FONTS['small']).pack(pady=(8, 0))
        tk.Label(self, textvariable=self._val_var,
                 bg=COLORS['surface2'], fg=accent,
                 font=('Segoe UI', 20, 'bold')).pack(pady=(0, 8))

    def set(self, value):
        self._val_var.set(str(value))


# ──────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ──────────────────────────────────────────────────────────────────────────────

class SBOMParserApp(tk.Tk):

    _FILTER_PLACEHOLDER = 'Filter components…'

    def __init__(self):
        super().__init__()
        self.title('SBOM Parser v3.0')
        self.geometry('1150x800')
        self.minsize(950, 660)
        self.configure(bg=COLORS['bg'])

        # ── state ─────────────────────────────────────────────────────────────
        self._components   : list = []
        self._sort_reverse : dict = {col: False for col in COLUMNS}

        # ── tk variables (ALL created before _build_ui) ───────────────────────
        self._input_path  = tk.StringVar()
        self._output_path = tk.StringVar()
        self._status_msg  = tk.StringVar(
            value='Ready — load an SBOM file to begin.')
        self._filter_var  = tk.StringVar()
        self._filter_col  = tk.StringVar(value='All')

        # ── build UI ──────────────────────────────────────────────────────────
        self._setup_styles()
        self._build_ui()

        # ── attach filter trace AFTER all widgets exist ───────────────────────
        self._filter_var.trace_add('write', self._apply_filter)

    # ── ttk styles ────────────────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')

        style.configure('Treeview',
                        background      = COLORS['row_even'],
                        foreground      = COLORS['text'],
                        fieldbackground = COLORS['row_even'],
                        rowheight       = 26,
                        font            = FONTS['small'])
        style.configure('Treeview.Heading',
                        background = COLORS['header_bg'],
                        foreground = COLORS['secondary'],
                        font       = FONTS['heading'],
                        relief     = 'flat')
        style.map('Treeview',
                  background=[('selected', COLORS['primary'])],
                  foreground=[('selected', '#FFFFFF')])
        style.map('Treeview.Heading',
                  background=[('active', COLORS['primary'])])
        style.configure('Vertical.TScrollbar',
                        background  = COLORS['surface2'],
                        troughcolor = COLORS['surface'],
                        arrowcolor  = COLORS['text_dim'])
        style.configure('Horizontal.TScrollbar',
                        background  = COLORS['surface2'],
                        troughcolor = COLORS['surface'],
                        arrowcolor  = COLORS['text_dim'])
        style.configure('TProgressbar',
                        troughcolor = COLORS['surface2'],
                        background  = COLORS['primary'],
                        thickness   = 6)
        style.configure('TCombobox',
                        fieldbackground = COLORS['surface2'],
                        background      = COLORS['surface2'],
                        foreground      = COLORS['text'],
                        arrowcolor      = COLORS['text_dim'])
        style.map('TCombobox',
                  fieldbackground=[('readonly', COLORS['surface2'])],
                  foreground      =[('readonly', COLORS['text'])])

    # ── top-level layout ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_body()
        self._build_statusbar()

    # ── header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=COLORS['surface'], height=70)
        hdr.pack(fill='x', side='top')
        hdr.pack_propagate(False)

        title_f = tk.Frame(hdr, bg=COLORS['surface'])
        title_f.pack(side='left', padx=20, pady=10)

        tk.Label(title_f, text='⬡',
                 bg=COLORS['surface'], fg=COLORS['primary'],
                 font=('Segoe UI', 22, 'bold')).pack(side='left', padx=(0, 8))
        tk.Label(title_f, text='SPDX SBOM Parser',
                 bg=COLORS['surface'], fg=COLORS['text'],
                 font=FONTS['title']).pack(side='left')
        tk.Label(title_f, text='  v3.0',
                 bg=COLORS['surface'], fg=COLORS['text_dim'],
                 font=FONTS['body']).pack(side='left', pady=(6, 0))

        tk.Frame(self, bg=COLORS['border'], height=1).pack(fill='x')

    # ── body ──────────────────────────────────────────────────────────────────

    def _build_body(self):
        body = tk.Frame(self, bg=COLORS['bg'])
        body.pack(fill='both', expand=True, padx=16, pady=12)

        left = tk.Frame(body, bg=COLORS['bg'], width=300)
        left.pack(side='left', fill='y', padx=(0, 12))
        left.pack_propagate(False)
        self._build_left_panel(left)

        right = tk.Frame(body, bg=COLORS['bg'])
        right.pack(side='left', fill='both', expand=True)
        self._build_right_panel(right)

    # ── left panel ────────────────────────────────────────────────────────────

    def _build_left_panel(self, parent):
        file_card = self._make_card(parent, '📂  File Selection')
        file_card.pack(fill='x', pady=(0, 10))
        self._build_file_row(file_card, 'SBOM Input File',
                             self._input_path, self._browse_input)
        self._build_file_row(file_card, 'CSV Output File',
                             self._output_path, self._browse_output,
                             bottom_pad=12)

        act_card = self._make_card(parent, '⚙️  Actions')
        act_card.pack(fill='x', pady=(0, 10))
        btn_f = tk.Frame(act_card, bg=COLORS['surface'])
        btn_f.pack(fill='x', padx=12, pady=10)

        self._parse_btn = RoundedButton(
            btn_f, text='▶  Parse SBOM',
            command=self._start_parse,
            width=260, height=40,
            bg=COLORS['primary'], hover=COLORS['primary_hover'])
        self._parse_btn.pack(pady=(0, 8))

        self._save_btn = RoundedButton(
            btn_f, text='💾  Save CSV',
            command=self._save_csv,
            width=260, height=40,
            bg=COLORS['success'], hover='#3BB88E')
        self._save_btn.pack(pady=(0, 8))

        RoundedButton(btn_f, text='🗑  Clear All',
                      command=self._clear,
                      width=260, height=40,
                      bg=COLORS['surface2'], hover=COLORS['border']
                      ).pack()

        prog_card = self._make_card(parent, '⏳  Progress')
        prog_card.pack(fill='x', pady=(0, 10))
        self._progress = ttk.Progressbar(prog_card, mode='indeterminate',
                                         style='TProgressbar')
        self._progress.pack(fill='x', padx=12, pady=10)

        stat_card = self._make_card(parent, '📊  Statistics')
        stat_card.pack(fill='x')
        grid = tk.Frame(stat_card, bg=COLORS['surface'])
        grid.pack(fill='x', padx=12, pady=10)
        grid.columnconfigure((0, 1), weight=1)

        self._stat_total    = StatCard(grid, 'Total',     accent=COLORS['primary'])
        self._stat_purl     = StatCard(grid, 'With PURL', accent=COLORS['secondary'])
        self._stat_no_purl  = StatCard(grid, 'No PURL',   accent=COLORS['warning'])
        self._stat_licenses = StatCard(grid, 'Licenses',  accent=COLORS['success'])

        self._stat_total.grid(   row=0, column=0, padx=4, pady=4, sticky='nsew')
        self._stat_purl.grid(    row=0, column=1, padx=4, pady=4, sticky='nsew')
        self._stat_no_purl.grid( row=1, column=0, padx=4, pady=4, sticky='nsew')
        self._stat_licenses.grid(row=1, column=1, padx=4, pady=4, sticky='nsew')

    def _build_file_row(self, parent, label_text, string_var,
                        browse_cmd, bottom_pad=8):
        tk.Label(parent, text=label_text,
                 bg=COLORS['surface'], fg=COLORS['text_dim'],
                 font=FONTS['small']).pack(anchor='w', padx=12, pady=(4, 2))
        row = tk.Frame(parent, bg=COLORS['surface'])
        row.pack(fill='x', padx=12, pady=(0, bottom_pad))
        entry = tk.Entry(row, textvariable=string_var,
                         bg=COLORS['surface2'], fg=COLORS['text'],
                         insertbackground=COLORS['text'],
                         relief='flat', font=FONTS['mono'],
                         highlightthickness=1,
                         highlightbackground=COLORS['border'],
                         highlightcolor=COLORS['primary'])
        entry.pack(side='left', fill='x', expand=True, ipady=5, padx=(0, 6))
        tk.Button(row, text='Browse',
                  bg=COLORS['primary'], fg=COLORS['text'],
                  activebackground=COLORS['primary_hover'],
                  activeforeground=COLORS['text'],
                  relief='flat', font=FONTS['small'],
                  cursor='hand2', command=browse_cmd,
                  padx=8, pady=4).pack(side='left')

    # ── right panel ───────────────────────────────────────────────────────────

    def _build_right_panel(self, parent):
        self._build_filter_bar(parent)
        self._build_treeview(parent)
        self._build_detail_panel(parent)

    def _build_filter_bar(self, parent):
        bar = tk.Frame(parent, bg=COLORS['surface'],
                       highlightbackground=COLORS['border'],
                       highlightthickness=1)
        bar.pack(fill='x', pady=(0, 8))

        tk.Label(bar, text='🔍',
                 bg=COLORS['surface'], fg=COLORS['text_dim'],
                 font=FONTS['body']).pack(side='left', padx=(10, 4), pady=8)

        self._filter_entry = tk.Entry(
            bar,
            textvariable=self._filter_var,
            bg=COLORS['surface'], fg=COLORS['text_dim'],
            insertbackground=COLORS['text'],
            relief='flat', font=FONTS['body'],
            highlightthickness=0)
        self._filter_entry.pack(side='left', fill='x', expand=True, ipady=6)
        self._filter_entry.insert(0, self._FILTER_PLACEHOLDER)
        self._filter_entry.bind('<FocusIn>',  self._filter_focus_in)
        self._filter_entry.bind('<FocusOut>', self._filter_focus_out)

        tk.Label(bar, text='Column:',
                 bg=COLORS['surface'], fg=COLORS['text_dim'],
                 font=FONTS['small']).pack(side='left', padx=(12, 4))

        col_choices = ['All'] + list(COLUMNS)
        self._col_combo = ttk.Combobox(
            bar,
            textvariable=self._filter_col,
            values=col_choices,
            state='readonly',
            width=24,
            font=FONTS['small'])
        self._col_combo.pack(side='left', padx=(0, 10), pady=6)
        self._col_combo.bind('<<ComboboxSelected>>',
                             lambda _: self._apply_filter())

        tk.Button(bar, text='✕ Clear',
                  bg=COLORS['surface2'], fg=COLORS['text_dim'],
                  activebackground=COLORS['border'],
                  activeforeground=COLORS['text'],
                  relief='flat', font=FONTS['small'],
                  cursor='hand2', padx=6, pady=3,
                  command=self._clear_filter).pack(side='left', padx=(0, 8))

    def _build_treeview(self, parent):
        tree_frame = tk.Frame(parent, bg=COLORS['surface'])
        tree_frame.pack(fill='both', expand=True)

        display_cols = [c for c in COLUMNS if c != 'Name']
        self._tree = ttk.Treeview(tree_frame, columns=COLUMNS, displaycolumns=display_cols,
                                  show='tree headings', selectmode='browse')
        
        self._tree.heading('#0', text='Name', command=lambda: self._sort_column('#0'))
        self._tree.column('#0', width=COL_WIDTHS.get('Name', 130) + 40, minwidth=100, anchor='w')

        for col in COLUMNS:
            self._tree.heading(
                col,
                text=col.replace('_', ' '),
                command=lambda c=col: self._sort_column(c))
            self._tree.column(col,
                              width=COL_WIDTHS.get(col, 100),
                              minwidth=60, anchor='w')

        self._tree.tag_configure('odd',     background=COLORS['row_odd'])
        self._tree.tag_configure('even',    background=COLORS['row_even'])
        self._tree.tag_configure('no_purl', foreground=COLORS['warning'])

        vsb = ttk.Scrollbar(tree_frame, orient='vertical',
                            command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient='horizontal',
                            command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind('<<TreeviewSelect>>', self._on_row_select)

    def _build_detail_panel(self, parent):
        self._detail_frame = tk.Frame(
            parent,
            bg=COLORS['surface2'],
            highlightbackground=COLORS['border'],
            highlightthickness=1)
        self._detail_frame.pack(fill='x', pady=(8, 0))

        tk.Label(self._detail_frame, text='ℹ️  Details',
                 bg=COLORS['surface2'], fg=COLORS['secondary'],
                 font=FONTS['heading']).pack(anchor='w', padx=10, pady=(6, 2))

        self._detail_text = tk.Text(
            self._detail_frame,
            bg=COLORS['surface2'], fg=COLORS['text'],
            font=FONTS['mono'],
            height=4, relief='flat',
            wrap='word',
            state='disabled',
            highlightthickness=0)
        self._detail_text.pack(fill='x', padx=10, pady=(0, 8))

    # ── status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        tk.Frame(self, bg=COLORS['border'], height=1).pack(fill='x')
        bar = tk.Frame(self, bg=COLORS['surface'], height=28)
        bar.pack(fill='x', side='bottom')
        bar.pack_propagate(False)

        self._status_dot = tk.Label(bar, text='●',
                                    bg=COLORS['surface'],
                                    fg=COLORS['text_dim'],
                                    font=FONTS['small'])
        self._status_dot.pack(side='left', padx=(10, 4))
        tk.Label(bar, textvariable=self._status_msg,
                 bg=COLORS['surface'], fg=COLORS['text_dim'],
                 font=FONTS['small']).pack(side='left')

        self._time_label = tk.Label(bar, text='',
                                    bg=COLORS['surface'],
                                    fg=COLORS['text_dim'],
                                    font=FONTS['small'])
        self._time_label.pack(side='right', padx=10)
        self._tick_clock()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _make_card(self, parent, title):
        outer = tk.Frame(parent, bg=COLORS['surface'],
                         highlightbackground=COLORS['border'],
                         highlightthickness=1)
        tk.Label(outer, text=title,
                 bg=COLORS['surface'], fg=COLORS['secondary'],
                 font=FONTS['heading']).pack(anchor='w', padx=12, pady=(8, 4))
        tk.Frame(outer, bg=COLORS['border'], height=1).pack(fill='x', padx=8)
        return outer

    def _set_status(self, msg, colour=COLORS['text_dim']):
        self._status_msg.set(msg)
        self._status_dot.configure(fg=colour)

    def _tick_clock(self):
        self._time_label.configure(
            text=datetime.now().strftime('%Y-%m-%d  %H:%M:%S'))
        self.after(1000, self._tick_clock)

    # ── filter helpers ────────────────────────────────────────────────────────

    def _filter_focus_in(self, _):
        if self._filter_entry.get() == self._FILTER_PLACEHOLDER:
            self._filter_entry.delete(0, 'end')
            self._filter_entry.configure(fg=COLORS['text'])

    def _filter_focus_out(self, _):
        if not self._filter_entry.get().strip():
            self._filter_entry.insert(0, self._FILTER_PLACEHOLDER)
            self._filter_entry.configure(fg=COLORS['text_dim'])

    def _clear_filter(self):
        self._filter_entry.delete(0, 'end')
        self._filter_entry.insert(0, self._FILTER_PLACEHOLDER)
        self._filter_entry.configure(fg=COLORS['text_dim'])
        self._filter_col.set('All')
        self._populate_table(self._components)
        self._set_status(
            f'Filter cleared — showing all {len(self._components)} components.',
            COLORS['text_dim'])

    # ── file browsing ─────────────────────────────────────────────────────────

    def _browse_input(self):
        path = filedialog.askopenfilename(
            title='Select SPDX SBOM File',
            filetypes=[
                ('SPDX Files', '*.json *.spdx *.tv *.xml'),
                ('JSON',       '*.json'),
                ('SPDX TV',    '*.spdx *.tv'),
                ('XML',        '*.xml'),
                ('All Files',  '*.*'),
            ])
        if path:
            self._input_path.set(path)
            if not self._output_path.get():
                base = os.path.splitext(path)[0]
                ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
                self._output_path.set(f"{base}_components_{ts}.csv")
            self._set_status(
                f'Input selected: {os.path.basename(path)}',
                COLORS['secondary'])

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            title='Save CSV As',
            defaultextension='.csv',
            filetypes=[('CSV Files', '*.csv'), ('All Files', '*.*')])
        if path:
            self._output_path.set(path)

    # ── parsing ───────────────────────────────────────────────────────────────

    def _start_parse(self):
        input_file = self._input_path.get().strip()
        if not input_file:
            messagebox.showwarning('No Input File',
                                   'Please select an SBOM input file first.')
            return
        if not os.path.exists(input_file):
            messagebox.showerror('File Not Found',
                                 f'Cannot find:\n{input_file}')
            return

        self._progress.start(10)
        self._parse_btn.set_enabled(False)
        self._set_status('Parsing SBOM…', COLORS['warning'])
        self._clear_table()

        threading.Thread(target=self._parse_worker,
                         args=(input_file,), daemon=True).start()

    def _parse_worker(self, input_file):
        try:
            components, relationships = parse_sbom(input_file)
            self.after(0, self._on_parse_success, components, relationships)
        except Exception as exc:
            self.after(0, self._on_parse_error, str(exc))

    def _build_tree_data(self, components, relationships):
        if not relationships:
            for c in components:
                c['depth'] = 0
            return components

        comp_map = {c['SPDX_ID']: c for c in components}
        children = {c['SPDX_ID']: [] for c in components}
        parents = {c['SPDX_ID']: [] for c in components}
        
        for rel in relationships:
            p = rel['parent']
            c = rel['child']
            if p in comp_map and c in comp_map:
                if c not in children[p]:
                    children[p].append(c)
                if p not in parents[c]:
                    parents[c].append(p)

        roots = [c_id for c_id in comp_map if not parents[c_id]]
        if not roots:
            roots = list(comp_map.keys())

        result = []
        visited = set()

        def dfs(c_id, parent_id, depth, tree_id):
            if c_id in visited:
                return
            visited.add(c_id)
            comp = comp_map[c_id].copy()
            comp['depth'] = depth
            comp['tree_parent'] = parent_id
            comp['Tree_ID'] = tree_id
            result.append(comp)
            
            for idx, child_id in enumerate(children.get(c_id, []), start=1):
                dfs(child_id, c_id, depth + 1, f"{tree_id}.{idx}")

        for idx, r_id in enumerate(roots, start=1):
            dfs(r_id, '', 0, str(idx))
            
        unvisited = [c_id for c_id in comp_map if c_id not in visited]
        for idx, c_id in enumerate(unvisited, start=len(roots) + 1):
            dfs(c_id, '', 0, str(idx))

        return result

    def _on_parse_success(self, components, relationships):
        self._progress.stop()
        self._parse_btn.set_enabled(True)
        tree_components = self._build_tree_data(components, relationships)
        self._components = tree_components
        self._populate_table(tree_components)
        self._update_stats(tree_components)
        self._set_status(
            f'✔  Parsed {len(components)} components successfully.',
            COLORS['success'])

    def _on_parse_error(self, error):
        self._progress.stop()
        self._parse_btn.set_enabled(True)
        self._set_status(f'✖  Error: {error}', COLORS['error'])
        messagebox.showerror('Parse Error',
                             f'Failed to parse SBOM:\n\n{error}')

    # ── table ─────────────────────────────────────────────────────────────────

    def _populate_table(self, components):
        self._clear_table()
        iid_map = {}
        for i, comp in enumerate(components):
            base_tag = 'odd' if i % 2 else 'even'
            tags     = (base_tag, 'no_purl') \
                       if comp.get('Package_Manager_Locator', 'N/A') == 'N/A' \
                       else (base_tag,)
            
            values = [comp.get(col, '') for col in COLUMNS]
            
            parent_spdx = comp.get('tree_parent', '')
            parent_iid = iid_map.get(parent_spdx, '')
            
            my_iid = str(i)
            iid_map[comp['SPDX_ID']] = my_iid
            
            self._tree.insert(parent_iid, 'end', iid=my_iid,
                              text=comp.get('Name', ''),
                              values=tuple(values),
                              tags=tags,
                              open=True)

    def _clear_table(self):
        self._tree.delete(*self._tree.get_children())

    def _update_stats(self, components):
        total    = len(components)
        with_p   = sum(1 for c in components
                       if c['Package_Manager_Locator'] != 'N/A')
        licenses = len({c['License_Declared'] for c in components
                        if c['License_Declared'] not in
                        ('N/A', 'NOASSERTION', '')})
        self._stat_total.set(total)
        self._stat_purl.set(with_p)
        self._stat_no_purl.set(total - with_p)
        self._stat_licenses.set(licenses)

    # ── filter ────────────────────────────────────────────────────────────────

    def _apply_filter(self, *_):
        if not hasattr(self, '_filter_col') or not hasattr(self, '_tree'):
            return
        if not self._components:
            return

        raw   = self._filter_var.get().strip()
        query = '' if raw == self._FILTER_PLACEHOLDER else raw.lower()
        col   = self._filter_col.get()

        if not query:
            self._populate_table(self._components)
            self._set_status(
                f'Showing all {len(self._components)} components.',
                COLORS['text_dim'])
            return

        col_keys = list(COLUMNS)
        filtered = []
        for comp in self._components:
            values = list(comp.values())
            if col == 'All':
                match = any(query in str(v).lower() for v in values)
            else:
                idx   = col_keys.index(col) if col in col_keys else 0
                match = query in str(values[idx]).lower()
            if match:
                filtered.append(comp)

        self._populate_table(filtered)
        self._set_status(
            f'Filter: {len(filtered)} of {len(self._components)} shown.',
            COLORS['secondary'])

    # ── sort ──────────────────────────────────────────────────────────────────

    def _sort_column(self, col):
        reverse = self._sort_reverse.get(col, False)
        if col == '#0':
            data = [(self._tree.item(child, 'text'), child)
                    for child in self._tree.get_children('')]
        else:
            data = [(self._tree.set(child, col), child)
                    for child in self._tree.get_children('')]
        data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for idx, (_, child) in enumerate(data):
            self._tree.move(child, '', idx)
            tag      = 'odd' if idx % 2 else 'even'
            cur_tags = list(self._tree.item(child, 'tags'))
            new_tags = [t for t in cur_tags
                        if t not in ('odd', 'even')] + [tag]
            self._tree.item(child, tags=new_tags)
        self._sort_reverse[col] = not reverse

    # ── row detail ────────────────────────────────────────────────────────────

    def _on_row_select(self, _):
        selected = self._tree.selection()
        if not selected or not self._components:
            return
        values = self._tree.item(selected[0], 'values')
        lines  = '\n'.join(
            f'{k:<28}: {v}'
            for k, v in zip(COLUMNS, values)
            if v and v != 'N/A'
        )
        self._detail_text.configure(state='normal')
        self._detail_text.delete('3.0', 'end')
        self._detail_text.insert('end', lines or 'No data available.')
        self._detail_text.configure(state='disabled')

    # ── save CSV ──────────────────────────────────────────────────────────────

    def _save_csv(self):
        if not self._components:
            messagebox.showwarning('No Data',
                                   'Parse an SBOM file first before saving.')
            return

        output_file = self._output_path.get().strip()
        if not output_file:
            output_file = filedialog.asksaveasfilename(
                title='Save CSV As',
                defaultextension='.csv',
                filetypes=[('CSV Files', '*.csv')])
            if not output_file:
                return
            self._output_path.set(output_file)

        try:
            save_to_csv(self._components, output_file)
            self._set_status(
                f'✔  Saved {len(self._components)} rows → '
                f'{os.path.basename(output_file)}',
                COLORS['success'])
            if messagebox.askyesno(
                    'Saved!',
                    f'CSV saved successfully!\n\n{output_file}'
                    '\n\nOpen the file now?'):
                self._open_file(output_file)
        except Exception as exc:
            messagebox.showerror('Save Error',
                                 f'Could not save CSV:\n\n{exc}')

    @staticmethod
    def _open_file(path):
        if sys.platform == 'win32':
            os.startfile(path)
        elif sys.platform == 'darwin':
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')

    # ── clear all ─────────────────────────────────────────────────────────────

    def _clear(self):
        self._components = []
        self._clear_table()
        self._input_path.set('')
        self._output_path.set('')
        self._filter_col.set('All')

        self._filter_entry.delete(0, 'end')
        self._filter_entry.insert(0, self._FILTER_PLACEHOLDER)
        self._filter_entry.configure(fg=COLORS['text_dim'])

        self._stat_total.set(0)
        self._stat_purl.set(0)
        self._stat_no_purl.set(0)
        self._stat_licenses.set(0)

        self._detail_text.configure(state='normal')
        self._detail_text.delete('3.0', 'end')
        self._detail_text.configure(state='disabled')

        self._set_status('Cleared — ready for a new file.', COLORS['text_dim'])


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = SBOMParserApp()
    app.mainloop()