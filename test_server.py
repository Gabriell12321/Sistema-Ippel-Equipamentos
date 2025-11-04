#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/api/charts/biweekly-data')
def get_biweekly_chart_data():
    """API para testar dados dos gráficos por quinzena"""
    try:
        year = request.args.get('year', str(datetime.now().year), type=str)
        month = request.args.get('month', str(datetime.now().month).zfill(2), type=str)
        
        print(f"Gerando dados de teste para {month}/{year}")
        
        # Dados de exemplo para demonstração
        total_quinzena_1 = 7
        total_quinzena_2 = 12
        
        result = {
            'period': f"{month}/{year}",
            'quinzenas': [
                {
                    'label': f'1ª Quinzena (01-15/{month})',
                    'count': total_quinzena_1,
                    'days': 10,
                    'average': round(total_quinzena_1 / 15, 2)
                },
                {
                    'label': f'2ª Quinzena (16-31/{month})',
                    'count': total_quinzena_2,
                    'days': 8,
                    'average': round(total_quinzena_2 / 16, 2)
                }
            ],
            'total': total_quinzena_1 + total_quinzena_2,
            'daily_breakdown': {
                'quinzena_1': dict(zip(range(1, 16), [0] * 15)),
                'quinzena_2': dict(zip(range(16, 32), [0] * 16))
            }
        }
        
        print(f"Retornando dados: {json.dumps(result, indent=2)}")
        return jsonify(result)
        
    except Exception as e:
        print(f"Erro: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Teste API Quinzenas</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    </head>
    <body>
        <h1>🚦 Teste API de Quinzenas</h1>
        <button onclick="testAPI()">Testar API</button>
        <div id="result"></div>
        <div style="width: 600px; height: 400px; margin: 20px 0;">
            <canvas id="chart"></canvas>
        </div>
        
        <script>
            let chart = null;
            
            async function testAPI() {
                try {
                    const response = await fetch('/api/charts/biweekly-data?year=2025&month=11');
                    const data = await response.json();
                    
                    document.getElementById('result').innerHTML = 
                        '<h2>Resultado da API:</h2><pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    
                    createChart(data);
                } catch (error) {
                    document.getElementById('result').innerHTML = 
                        '<h2>Erro:</h2><p>' + error.message + '</p>';
                }
            }
            
            function createChart(data) {
                const ctx = document.getElementById('chart');
                
                if (chart) chart.destroy();
                
                chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.quinzenas.map(q => q.label),
                        datasets: [{
                            label: 'RNCs por Quinzena',
                            data: data.quinzenas.map(q => q.count),
                            backgroundColor: ['rgba(156, 39, 176, 0.8)', 'rgba(76, 175, 80, 0.8)'],
                            borderColor: ['rgba(156, 39, 176, 1)', 'rgba(76, 175, 80, 1)'],
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'RNCs por Quinzena - ' + data.period
                            }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            }
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("Iniciando servidor de teste...")
    app.run(debug=True, port=5003, host='0.0.0.0')