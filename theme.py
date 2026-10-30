# theme.py

TEMAS_DISPONIBLES = {

    "🌙 Modo Oscuro": {
        "bg_app": "#0e1117",
        "bg_sidebar": "#161b22",

        "text_main": "#e6edf3",
        "text_sub": "#8b949e",

        "bg_card": "rgba(22,27,34,0.70)",
        "border_card": "#30363d",

        "accent": "#2f81f7",

        "hover_bg": "rgba(56,139,253,0.15)",
        "hover_border": "#58a6ff",

        "input_bg": "#0d1117",
        "input_text": "#e6edf3",

        "chart_bg": "#0e1117",
        "chart_text": "#e6edf3",
        "chart_grid": "#30363d",
        "chart_border": "#8b949e"
    },

    "🏥 Tema MINSA (Institucional)": {
        "bg_app": "#071b26",
        "bg_sidebar": "#0c2533",

        "text_main": "#e0f2f1",
        "text_sub": "#9cc7c2",

        "bg_card": "rgba(0,150,136,0.12)",
        "border_card": "rgba(0,150,136,0.35)",

        "accent": "#00bcd4",

        "hover_bg": "rgba(0,150,136,0.22)",
        "hover_border": "#00bcd4",

        "input_bg": "#0c2533",
        "input_text": "#e0f2f1",

        "chart_bg": "#071b26",
        "chart_text": "#e0f2f1",
        "chart_grid": "#1f4d5f",
        "chart_border": "#00bcd4"
    },

    "☀️ Modo Claro": {
        "bg_app": "#f1f5f9",
        "bg_sidebar": "#ffffff",

        "text_main": "#111827",
        "text_sub": "#6b7280",

        "bg_card": "#ffffff",
        "border_card": "#d1d5db",

        "accent": "#2563eb",

        "hover_bg": "rgba(37,99,235,0.08)",
        "hover_border": "#2563eb",

        "input_bg": "#ffffff",
        "input_text": "#111827",

        "chart_bg": "#ffffff",
        "chart_text": "#111827",
        "chart_grid": "#d1d5db",
        "chart_border": "#6b7280"
    }
}

import streamlit as st

def get_theme(estilos):

    return {
        "CARD_BG": estilos["bg_card"],
        "CARD_BORDER": estilos["border_card"],

        "TEXT_MAIN": estilos["text_main"],
        "TEXT_SUB": estilos["text_sub"],

        "CHART_BG": estilos["chart_bg"],
        "CHART_TEXT": estilos["chart_text"],
        "CHART_GRID": estilos["chart_grid"],
        "CHART_BORDER": estilos["chart_border"],

        "ACCENT": estilos["accent"]
    }

def apply_theme_css(estilos):

    st.markdown(f"""
    <style>

    /* Fondo general */
    [data-testid="stAppViewContainer"] {{
        background-color: {estilos["bg_app"]} !important;
    }}

    .main {{
        background-color: {estilos["bg_app"]} !important;
    }}

    body {{
        color: {estilos["text_main"]} !important;
    }}

    /* Sidebar */
    [data-testid="stSidebar"] {{
        background-color: {estilos["bg_sidebar"]} !important;
        border-right: 1px solid {estilos["border_card"]} !important;
    }}

    /* Titulos */
    h1,h2,h3,h4,h5,h6 {{
        color: {estilos["text_main"]} !important;
        font-weight: 600 !important;
    }}

    /* Labels */
    label,
    [data-testid="stMetricLabel"] {{
        color: {estilos["text_sub"]} !important;
    }}

    /* Inputs */
    input,
    textarea,
    div[data-baseweb="select"] > div,
    div[data-baseweb="base-input"],
    div[data-baseweb="input"],
    div[data-baseweb="calendar"] {{

        background-color: {estilos["input_bg"]} !important;
        color: {estilos["input_text"]} !important;

        border: 1px solid {estilos["border_card"]} !important;
        border-radius: 6px !important;
    }}

    /* Selectbox */
    div[data-baseweb="select"] * {{
        color: {estilos["input_text"]} !important;
    }}

    /* Date Input */
    [data-testid="stDateInput"] input {{
        color: {estilos["input_text"]} !important;
    }}

    /* Focus */
    div[data-baseweb="input"]:focus-within,
    div[data-baseweb="select"]:focus-within > div {{

        border-color: {estilos["accent"]} !important;
        box-shadow: 0 0 0 3px rgba(47,129,247,0.2) !important;
    }}

    /* DataFrames */
    [data-testid="stDataFrame"],
    [data-testid="stTable"],
    .stDataFrame {{

        background-color: {estilos["bg_card"]} !important;

        border: 1px solid {estilos["border_card"]} !important;

        border-radius: 10px !important;

        color: {estilos["text_main"]} !important;
    }}

    /* Botones */
    .stButton > button {{

        background-color: {estilos["accent"]} !important;

        color: white !important;

        border: 1px solid {estilos["border_card"]} !important;

        border-radius: 8px !important;

        font-weight: 600 !important;
    }}

    .stButton > button:hover {{
        opacity: .92 !important;
    }}

    /* Sidebar botones */
    [data-testid="stSidebar"] .stButton > button {{

        background-color: {estilos["bg_card"]} !important;

        color: {estilos["text_main"]} !important;

        border: 1px solid {estilos["border_card"]} !important;

        text-align: left !important;
    }}

    [data-testid="stSidebar"] .stButton > button:hover {{

        background-color: {estilos["hover_bg"]} !important;

        border-color: {estilos["hover_border"]} !important;
    }}

    /* Ocultar componentes */
    #MainMenu {{
        visibility:hidden;
    }}

    footer {{
        visibility:hidden;
    }}

    button[title*="Deploy"] {{
        display:none !important;
    }}

    </style>
    """, unsafe_allow_html=True)

    print("THEME.PY CARGADO CORRECTAMENTE")