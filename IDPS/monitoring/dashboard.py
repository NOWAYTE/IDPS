import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
import json
import os
from config import BASE_DIR

app = dash.Dash(__name__)

def load_report():
    report_path = os.path.join(BASE_DIR, 'results', 'test_report.json')
    if os.path.exists(report_path):
        with open(report_path) as f:
            return json.load(f)
    return {}

app.layout = html.Div([
    html.H1("IoT IDPS Performance Dashboard"),
    dcc.Dropdown(
        id='scenario-selector',
        options=[{'label': s, 'value': s} for s in load_report().get('scenarios', {}).keys()],
        value='ddos_attack'
    ),
    dcc.Graph(id='metrics-graph'),
    dcc.Interval(id='refresh-interval', interval=60*1000, n_intervals=0)
])

@app.callback(
    Output('metrics-graph', 'figure'),
    [Input('scenario-selector', 'value'),
     Input('refresh-interval', 'n_intervals')]
)
def update_graph(scenario, n):
    report = load_report()
    scenario_data = report.get('scenarios', {}).get(scenario, {})
    
    if not scenario_data:
        return go.Figure()
    
    metrics = ['detection_events', 'avg_confidence', 'max_latency']
    values = [scenario_data.get(m, 0) for m in metrics]
    
    fig = go.Figure(data=[
        go.Bar(name='Metrics', x=metrics, y=values)
    ])
    
    fig.update_layout(
        title=f"Performance Metrics: {scenario}",
        yaxis_title="Value",
        showlegend=False
    )
    
    return fig

if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=8050, debug=True)