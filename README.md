# bigdata-ciberseguridad-spark
 Análisis de intrusiones de red con Apache Spark - UNAD Big Data
# Análisis de Intrusiones de Ciberseguridad con Apache Spark

## Descripción del problema
Detección de patrones de intrusión en redes a partir de datos de tráfico 
para identificar comportamientos maliciosos.

## Dataset
- **Fuente:** cybersecurity_intrusion_data.csv
- **Registros:** 9.537 sesiones de red
- **Variables:** 11 (protocol_type, encryption_used, 
  failed_logins, attack_detected, entre otras)
- **Tasa de intrusión:** 44.7%

## Tecnologías utilizadas
- Apache Spark 3.x (PySpark)
- Python 3.8+
- Matplotlib
- Pandas

## Estructura del repositorio
```
bigdata-ciberseguridad-spark/
│
├── analisis_batch_ciberseguridad.py  # Script principal de análisis
├── cybersecurity_intrusion_data.csv  # Dataset
└── README.md                         # Este archivo
```

## Instrucciones de ejecución

### 1. Requisitos previos
```bash
pip install pyspark matplotlib pandas
```

### 2. Clonar el repositorio
```bash
git clone https://github.com/AndersonPulidoA/bigdata-ciberseguridad-spark.git
cd bigdata-ciberseguridad-spark
```

### 3. Ejecutar el análisis batch
```bash
python3 analisis_batch_ciberseguridad.py
```

## Resultados obtenidos

| Métrica | Valor |
|---|---|
| Registros procesados | 9.537 |
| Tasa global de intrusión | 44.7% |
| Protocolo con mayor tasa de ataque | ICMP (~47%) |
| Cifrado más inseguro | None (sin cifrado) |
| Predictor más fuerte | ip_reputation_score < 0.2 |

## Análisis realizados
- Tasa de ataque por protocolo de red (TCP / UDP / ICMP)
- Impacto del tipo de cifrado en la seguridad
- Tasa de ataque por navegador
- Análisis regional con operaciones RDD
- Comparativa estadística sesiones con ataque vs sin ataque

## Autor
Nombre: Anderson Pulido
Curso: Big Data 
Universidad: UNAD
```
