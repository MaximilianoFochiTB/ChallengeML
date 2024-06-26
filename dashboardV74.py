import dash
from cryptography.fernet import Fernet
from dash import dcc, html
from dash.dependencies import Input, Output, State, ALL
import plotly.express as px
import pandas as pd
from sqlalchemy import create_engine
from transformers import pipeline
import dash_bootstrap_components as dbc
import logging
import json


# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Leer la clave de encriptación
with open('key.key', 'rb') as key_file:
    key = key_file.read()

cipher_suite = Fernet(key)

# Leer y desencriptar las credenciales de la base de datos
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

db_uri = cipher_suite.decrypt(config['db_uri'].encode('utf-8')).decode('utf-8')
db_user = cipher_suite.decrypt(config['db_user'].encode('utf-8')).decode('utf-8')
db_password = cipher_suite.decrypt(config['db_password'].encode('utf-8')).decode('utf-8')

# Configurar la conexión a la base de datos
engine = create_engine(f'{db_uri}?user={db_user}&password={db_password}')



# Leer los datos de la base de datos
logger.info("Leyendo datos de la base de datos")
df = pd.read_sql('SELECT * FROM vulnerabilidades', engine)

# Convertir las columnas de fechas a datetime
logger.info("Convirtiendo columnas de fechas a datetime")
df['date_added'] = pd.to_datetime(df['date_added'], errors='coerce')
df['due_date'] = pd.to_datetime(df['due_date'], errors='coerce')
df['pub_date'] = pd.to_datetime(df['pub_date'], errors='coerce')

# Inicializar el modelo de resumen y generación de texto
logger.info("Inicializando el modelo de resumen")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

logger.info("Inicializando el modelo de recomendaciones")
recommender = pipeline("text-generation", model="gpt2")

# Inicializar la aplicación Dash
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)

# Función para resumir una vulnerabilidad
def summarize_vulnerability(description):
    """
    Función que recibe una descripción detallada de una vulnerabilidad y retorna un resumen.
    """
    logger.info(f"Resumiendo descripción: {description[:50]}...")
    summary = summarizer(description, max_length=100, min_length=30, do_sample=False)
    return summary[0]['summary_text']

# Función para generar una recomendación basada en una descripción de vulnerabilidad
def generate_recommendation(description_vulnerability):
    logger.info(f"Generando recomendación para: {description_vulnerability[:50]}...")
    prompt = f"Genera recomendaciones para mitigar la vulnerabilidad: {description_vulnerability}"
    recommendation = recommender(prompt, max_length=150, num_return_sequences=1)[0]['generated_text']
    return recommendation

# Función para crear una lista paginada de vulnerabilidades
def create_vulnerability_list(page, page_size, search_text=None, filters=None):
    filtered_df = df.copy()
    if search_text:
        filtered_df = filtered_df[filtered_df['short_description'].str.contains(search_text, case=False, na=False)]
    if filters:
        for filter_col in filters:
            filtered_df = filtered_df[filtered_df[filter_col].notnull()]

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_df = filtered_df.iloc[start_idx:end_idx]

    vulnerability_list = [
        dbc.Card(
            dbc.CardBody([
                html.H5(f"Vulnerability: {row['cve_id']}"),
                html.H6(f"Vendor: {row['vendor_project']}"),
                html.H6(f"Product: {row['product']}"),
                html.P(f"Name: {row['vulnerability_name']}"),
                html.P(f"Severity: {row['severity']}"),
                html.P(f"Description: {row['short_description']}"),
                html.Div(id={'type': 'summary-container', 'index': row['id']}),
                dbc.Button('Click to view Summary & Recommendation', id={'type': 'select-button', 'index': row['id']}, color="primary")
            ])
        )
        for _, row in page_df.iterrows()
    ]
    return vulnerability_list, len(filtered_df)

# Layout del dashboard
app.layout = html.Div([
    html.H1("Dashboard de Vulnerabilidades de Ciberseguridad"),
    dcc.Tabs(id="tabs", value='tab-1', children=[
        dcc.Tab(label='Análisis', value='tab-1'),
        dcc.Tab(label='Lista de Vulnerabilidades', value='tab-2'),
    ]),
    html.Div(id='tabs-content')
])

# Callback para renderizar el contenido de las pestañas
@app.callback(Output('tabs-content', 'children'),
              Input('tabs', 'value'))
def render_content(tab):
    if tab == 'tab-1':
        return html.Div([
            dcc.Input(id='input-text', type='text', placeholder='Buscar vulnerabilidades...', debounce=True),
            dcc.Graph(id='search-results'),
            dcc.Graph(id='severity-distribution'),
            dcc.Graph(id='date-trend'),
            dcc.Graph(id='cvss-correlation'),
            dcc.Graph(id='vendor-project-distribution'),
            html.H2("Identificación de Patrones y Storytelling"),
            dcc.Markdown(id='storytelling'),
            html.H2("Gráficos Adicionales para Tomar Decisiones"),
            dcc.Graph(id='critical-vendors'),
            dcc.Graph(id='common-products'),
            dcc.Graph(id='cwe-distribution')
        ])
    elif tab == 'tab-2':
        return html.Div([
            html.H1("Lista de Vulnerabilidades"),
            dbc.Input(id='filter-text', type='text', placeholder='Buscar...', debounce=True, style={'margin-bottom': '10px'}),
            dcc.Dropdown(
                id='filter-dropdown',
                options=[
                    {'label': 'Vendor', 'value': 'vendor_project'},
                    {'label': 'Producto', 'value': 'product'},
                    {'label': 'CWE', 'value': 'cwe'},
                    {'label': 'Severidad', 'value': 'severity'}
                ],
                placeholder="Selecciona un filtro",
                multi=True,
                style={'margin-bottom': '10px'}
            ),
            dbc.Button('Buscar', id='filter-button', n_clicks=0, color="primary", style={'margin-bottom': '10px'}),
            html.Div(id='vulnerability-list'),
            dbc.Pagination(id='pagination', max_value=1, fully_expanded=False, first_last=True),
        ])

# Callback para actualizar la lista de vulnerabilidades con paginador
@app.callback(
    [Output('vulnerability-list', 'children'),
     Output('pagination', 'max_value')],
    [Input('filter-button', 'n_clicks'),
     Input('pagination', 'active_page')],
    [State('filter-text', 'value'), State('filter-dropdown', 'value')]
)
def update_vulnerability_list(n_clicks, active_page, search_text, filters):
    logger.info("Actualizando la lista de vulnerabilidades")
    page_size = 20
    if not active_page:
        active_page = 1
    vulnerabilities, total_vulnerabilities = create_vulnerability_list(active_page, page_size, search_text, filters)
    max_value = (total_vulnerabilities + page_size - 1) // page_size  # Calcular el número de páginas
    return vulnerabilities, max_value

# Callback para mostrar el resumen de la vulnerabilidad seleccionada
@app.callback(
    Output({'type': 'summary-container', 'index': ALL}, 'children'),
    [Input({'type': 'select-button', 'index': ALL}, 'n_clicks')]
)
def display_vulnerability_summary(n_clicks_list):
    ctx = dash.callback_context
    if not ctx.triggered:
        return [html.Div() for _ in n_clicks_list]
    else:
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
        button_id_dict = eval(triggered_id)
        vulnerability_id = button_id_dict['index']

        selected_vulnerability = df[df['id'] == vulnerability_id].iloc[0]
        summary_text = summarize_vulnerability(selected_vulnerability['short_description'])
        recommendation_text = generate_recommendation(selected_vulnerability['short_description'])

        summary_html = html.Div([
            html.H5("Summary", className="card-title"),
            html.P(summary_text, className="card-text"),
            html.H5("Recommendation", className="card-title"),
            html.P(recommendation_text, className="card-text")
        ], className="mt-3")

        return [summary_html if n_clicks else html.Div() for n_clicks in n_clicks_list]

# Callback para actualizar la distribución de severidad
@app.callback(
    Output('severity-distribution', 'figure'),
    Input('input-text', 'value')
)
def update_severity_distribution(search_text):
    logger.info("Actualizando la distribución de severidad")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    fig = px.histogram(filtered_df, x='severity', title='Distribución de Severidad')
    return fig

# Callback para actualizar la tendencia de fechas
@app.callback(
    Output('date-trend', 'figure'),
    Input('input-text', 'value')
)
def update_date_trend(search_text):
    """
    Callback para actualizar la tendencia de fechas de adición de vulnerabilidades.
    """
    logger.info("Actualizando la tendencia de fechas")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    fig = px.line(filtered_df, x='date_added', y='id', title='Tendencia de Fechas de Adición')
    return fig

# Callback para mostrar resultados de búsqueda severidad por vendor
@app.callback(
    Output('search-results', 'figure'),
    Input('input-text', 'value')
)
def update_search_results(search_text):
    """
    Callback para mostrar los resultados de búsqueda de vulnerabilidades.
    """
    logger.info("Actualizando los resultados de búsqueda severidad por vendor")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    fig = px.histogram(filtered_df, x='severity', color='vendor_project', title='Severidad por Vendor')
    return fig

# Callback para mostrar la correlación de CVSS
@app.callback(
    Output('cvss-correlation', 'figure'),
    Input('input-text', 'value')
)
def update_cvss_correlation(search_text):
    """
    Callback para mostrar la correlación entre CVSS y severidad.
    """
    logger.info("Actualizando la correlación de CVSS y severidad")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    fig = px.scatter(filtered_df, x='cvss', y='severity', color='vendor_project', title='Correlación CVSS y Severidad')
    return fig

# Callback para mostrar la distribución por vendor y proyecto
@app.callback(
    Output('vendor-project-distribution', 'figure'),
    Input('input-text', 'value')
)
def update_vendor_project_distribution(search_text):
    """
    Callback para mostrar la distribución de vulnerabilidades por vendor y proyecto.
    """
    logger.info("Actualizando la distribución por vendor y proyecto")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    fig = px.histogram(filtered_df, x='vendor_project', color='severity', title='Distribución por Vendor y Proyecto')
    return fig

# Callback para generar storytelling
@app.callback(
    Output('storytelling', 'children'),
    Input('input-text', 'value')
)
def update_storytelling(search_text):
    """
    Callback para generar un storytelling basado en los datos filtrados.
    """
    logger.info("Generando storytelling")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df

    high_severity_count = len(filtered_df[filtered_df['severity'] == 'CRITICAL'])
    common_vendors = filtered_df['vendor_project'].value_counts().head(3).index.tolist()
    avg_cvss = filtered_df['cvss'].mean()
    common_cwe = filtered_df['cwe'].value_counts().head(3).index.tolist()
    trend_over_time = filtered_df.groupby(filtered_df['date_added'].dt.to_period("M")).size()

    story = f"""
    ### Análisis de Vulnerabilidades
    - Número de vulnerabilidades de alta severidad (CRITICAL): **{high_severity_count}**
    - Vendors más comunes: **{', '.join(common_vendors)}**
    - Productos más comunes: **{', '.join(common_cwe)}**
    - Puntuación CVSS promedio: **{avg_cvss:.2f}**

    ### Hipótesis
    1. **Concentración de Vulnerabilidades Críticas**: La alta concentración de vulnerabilidades críticas en los vendors {', '.join(common_vendors)} sugiere que estos proveedores podrían tener procesos de seguridad más débiles o ser objetivos más frecuentes de ataques.
    2. **Productos Comunes Afectados**: Los productos más comunes afectados por vulnerabilidades son {', '.join(common_cwe)}, lo que podría indicar áreas específicas de debilidad en la industria.
    3. **Tendencia de Vulnerabilidades a lo Largo del Tiempo**: La tendencia de vulnerabilidades añadidas a lo largo del tiempo puede indicar períodos de mayor actividad de ataque o descubrimiento de vulnerabilidades.
    4. **Correlación entre CVSS y Severidad**: La puntuación CVSS promedio indica el nivel de gravedad general de las vulnerabilidades. Es importante observar la correlación entre la puntuación CVSS y la severidad para identificar patrones en la criticidad de las vulnerabilidades.
    """
    return story

# Callback para mostrar vendors con vulnerabilidades críticas
@app.callback(
    Output('critical-vendors', 'figure'),
    Input('input-text', 'value')
)
def update_critical_vendors(search_text):
    """
    Callback para mostrar los vendors con vulnerabilidades críticas.
    """
    logger.info("Actualizando vendors con vulnerabilidades críticas")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    critical_vendors = filtered_df[filtered_df['severity'] == 'CRITICAL']['vendor_project'].value_counts()
    fig = px.bar(critical_vendors, x=critical_vendors.index, y=critical_vendors.values, title='Vendors con Vulnerabilidades Críticas')
    return fig

# Callback para mostrar productos más comunes con vulnerabilidades
@app.callback(
    Output('common-products', 'figure'),
    Input('input-text', 'value')
)
def update_common_products(search_text):
    """
    Callback para mostrar los productos más comunes con vulnerabilidades.
    """
    logger.info("Actualizando productos más comunes con vulnerabilidades")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    common_products = filtered_df['product'].value_counts().head(10)
    fig = px.bar(common_products, x=common_products.index, y=common_products.values, title='Productos Más Comunes con Vulnerabilidades')
    return fig

# Callback para mostrar la distribución de CWE
@app.callback(
    Output('cwe-distribution', 'figure'),
    Input('input-text', 'value')
)
def update_cwe_distribution(search_text):
    """
    Callback para mostrar la distribución de CWE.
    """
    logger.info("Actualizando la distribución de CWE")
    if search_text:
        filtered_df = df[df['short_description'].str.contains(search_text, case=False, na=False)]
    else:
        filtered_df = df
    cwe_distribution = filtered_df['cwe'].value_counts().head(10)
    fig = px.bar(cwe_distribution, x=cwe_distribution.index, y=cwe_distribution.values, title='Distribución de CWE')
    return fig


if __name__ == '__main__':
    app.run_server(debug=True)
