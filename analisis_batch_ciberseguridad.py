"""
============================================================
  ANÁLISIS BATCH DE INTRUSIONES DE CIBERSEGURIDAD
  con Apache Spark (PySpark)

  Dataset: cybersecurity_intrusion_data.csv
  Variables:
    session_id, network_packet_size, protocol_type,
    login_attempts, session_duration, encryption_used,
    ip_reputation_score, failed_logins, browser_type,
    unusual_time_access, attack_detected (0/1)

  Resultado de Aprendizaje 2:
    Diseñar e implementar soluciones de almacenamiento y
    procesamiento de grandes volúmenes de datos con Spark.
============================================================
"""


# !pip install pyspark matplotlib pandas
# Coloca cybersecurity_intrusion_data.csv en el directorio de trabajo

# ── 1. IMPORTS Y SESIÓN SPARK
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, sum as _sum, avg, count, round as _round,
    when, desc, stddev, min as _min, max as _max, lit
)
from pyspark.sql.types import (
    StructType, StructField, StringType,
    IntegerType, FloatType, DoubleType
)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
import warnings

warnings.filterwarnings("ignore")

spark = (
    SparkSession.builder
    .appName("CiberseguridadIntrusion_Batch")
    .config("spark.sql.shuffle.partitions", "8")
    .config("spark.driver.memory", "2g")
    .getOrCreate()
)
spark.sparkContext.setLogLevel("ERROR")
print(f" SparkSession iniciada — versión Spark: {spark.version}\n")

# ── 2. SCHEMA EXPLÍCITO Y CARGA
schema = StructType([
    StructField("session_id",           StringType(),  True),
    StructField("network_packet_size",  IntegerType(), True),
    StructField("protocol_type",        StringType(),  True),
    StructField("login_attempts",       IntegerType(), True),
    StructField("session_duration",     DoubleType(),  True),
    StructField("encryption_used",      StringType(),  True),
    StructField("ip_reputation_score",  DoubleType(),  True),
    StructField("failed_logins",        IntegerType(), True),
    StructField("browser_type",         StringType(),  True),
    StructField("unusual_time_access",  IntegerType(), True),
    StructField("attack_detected",      IntegerType(), True),
])

ruta = "cybersecurity_intrusion_data.csv"

df_raw = spark.read.csv(
    ruta,
    header=True,
    schema=schema,
)
total_raw = df_raw.count()
print(f" Registros cargados : {total_raw:,}")
df_raw.printSchema()

# ── 3. LIMPIEZA Y EDA DE PREPARACIÓN
print("\n── Valores nulos por columna ──")
df_raw.select([
    _sum(col(c).isNull().cast("int")).alias(c)
    for c in df_raw.columns
]).show()

# Eliminar filas con nulos en columnas críticas
df = (
    df_raw
    .filter(col("attack_detected").isNotNull())
    .filter(col("network_packet_size").isNotNull())
    .filter(col("protocol_type").isNotNull())
    # Clamping de valores extremos en session_duration
    .filter(col("session_duration") >= 0)
)

# Columna auxiliar: sesión de alto riesgo
# (failed_logins >= 3 O ip_reputation_score < 0.2 O login_attempts >= 8)
df = df.withColumn(
    "alto_riesgo",
    when(
        (col("failed_logins") >= 3) |
        (col("ip_reputation_score") < 0.2) |
        (col("login_attempts") >= 8),
        1
    ).otherwise(0)
)

total = df.count()
print(f" Registros tras limpieza: {total:,}\n")
df.cache()   # Reutilización eficiente

# ── 4. ANÁLISIS CON DATAFRAMES

# 4.1 Distribución general de ataques detectados
print("── 4.1 Distribución de ataques ──")
df_ataques = (
    df.groupBy("attack_detected")
    .agg(count("*").alias("total"))
    .withColumn("porcentaje", _round(col("total") / lit(total) * 100, 2))
    .orderBy("attack_detected")
)
df_ataques.show()

# 4.2 Tasa de ataque por protocolo de red
print("── 4.2 Tasa de ataque por protocol_type ──")
df_protocolo = (
    df.groupBy("protocol_type")
    .agg(
        count("*").alias("sesiones"),
        _sum("attack_detected").alias("ataques"),
        _round(avg("attack_detected") * 100, 2).alias("tasa_ataque_pct"),
        _round(avg("network_packet_size"), 1).alias("pkt_promedio"),
    )
    .orderBy(desc("tasa_ataque_pct"))
)
df_protocolo.show()

# 4.3 Impacto del tipo de cifrado en la seguridad
print("── 4.3 Ataques por tipo de cifrado ──")
df_cifrado = (
    df.groupBy("encryption_used")
    .agg(
        count("*").alias("sesiones"),
        _sum("attack_detected").alias("ataques"),
        _round(avg("attack_detected") * 100, 2).alias("tasa_ataque_pct"),
        _round(avg("ip_reputation_score"), 4).alias("ip_rep_promedio"),
    )
    .orderBy(desc("tasa_ataque_pct"))
)
df_cifrado.show()

# 4.4 Navegadores más asociados a intrusiones
print("── 4.4 Tasa de ataque por browser_type ──")
df_browser = (
    df.groupBy("browser_type")
    .agg(
        count("*").alias("sesiones"),
        _sum("attack_detected").alias("ataques"),
        _round(avg("attack_detected") * 100, 2).alias("tasa_ataque_pct"),
        _round(avg("failed_logins"), 2).alias("failed_login_prom"),
    )
    .orderBy(desc("tasa_ataque_pct"))
)
df_browser.show()

# 4.5 Acceso en horario inusual vs ataque
print("── 4.5 Acceso inusual y su relación con ataques ──")
df_horario = (
    df.groupBy("unusual_time_access", "attack_detected")
    .agg(count("*").alias("total"))
    .orderBy("unusual_time_access", "attack_detected")
)
df_horario.show()

# ── 5. ANÁLISIS RDD (compatible con Python 3.13)
print("── 5. Estadísticas por protocolo y cifrado ──")

df_rdd_equiv = (
    df.groupBy("protocol_type", "encryption_used")
    .agg(
        _sum("attack_detected").alias("ataques"),
        count("*").alias("sesiones"),
        _round(avg("attack_detected") * 100, 2).alias("tasa_pct"),
        _round(avg("failed_logins"), 3).alias("failed_log_prom"),
        _round(avg("ip_reputation_score"), 4).alias("ip_rep_prom"),
    )
    .orderBy(col("tasa_pct").desc())
)
df_rdd_equiv.show()

print("\n Combinaciones con tasa de ataque > 45%:")
df_rdd_equiv.filter(col("tasa_pct") > 45).show()

print("\n── 5.2 Distribución de ip_reputation_score ──")
df.groupBy(
    when(col("ip_reputation_score") < 0.33, "bajo")
    .when(col("ip_reputation_score") < 0.66, "medio")
    .otherwise("alto").alias("categoria_ip")
).agg(
    count("*").alias("total_sesiones"),
    _sum("attack_detected").alias("ataques"),
    _round(avg("attack_detected") * 100, 2).alias("tasa_pct")
).orderBy("categoria_ip").show()

# ── 6. ANÁLISIS ESTADÍSTICO DESCRIPTIVO
print("\n── 6. Estadísticas descriptivas de variables numéricas ──")
df.select(
    "network_packet_size", "login_attempts",
    "session_duration", "ip_reputation_score", "failed_logins"
).describe().show()

# Comparativa ataque vs no-ataque
print("── Comparativa: sesiones con ataque vs sin ataque ──")
df.groupBy("attack_detected").agg(
    _round(avg("network_packet_size"),  1).alias("pkt_size_prom"),
    _round(avg("login_attempts"),       2).alias("login_att_prom"),
    _round(avg("session_duration"),     1).alias("duracion_prom"),
    _round(avg("ip_reputation_score"),  4).alias("ip_rep_prom"),
    _round(avg("failed_logins"),        2).alias("failed_log_prom"),
    _round(avg("unusual_time_access"),  3).alias("acc_inusual_prom"),
).orderBy("attack_detected").show()

# ── 7. VISUALIZACIÓN
plt.style.use("seaborn-v0_8-whitegrid")
fig, axes = plt.subplots(2, 3, figsize=(16, 9))
fig.suptitle(
    "Análisis de Intrusiones de Ciberseguridad — Apache Spark Batch",
    fontsize=14, fontweight="bold"
)

COLORS_ATK  = ["#2196F3", "#F44336"]   # azul = seguro, rojo = ataque
COLORS_PROT = ["#FF7043", "#66BB6A", "#AB47BC"]

# Gráfico 1: Distribución de ataques (pie)
ax1 = axes[0, 0]
at_pd = df_ataques.toPandas()
labels = ["Sin ataque", "Ataque detectado"]
wedge = dict(width=0.5, edgecolor="white", linewidth=2)
ax1.pie(at_pd["total"], labels=labels, autopct="%1.1f%%",
        colors=COLORS_ATK, wedgeprops=wedge, startangle=90)
ax1.set_title("Distribución de ataques detectados")

# Gráfico 2: Tasa de ataque por protocolo (barras)
ax2 = axes[0, 1]
pr_pd = df_protocolo.toPandas().sort_values("protocol_type")
bars = ax2.bar(pr_pd["protocol_type"], pr_pd["tasa_ataque_pct"],
               color=COLORS_PROT, edgecolor="white", linewidth=0.8)
ax2.set_xlabel("Protocolo"); ax2.set_ylabel("Tasa de ataque (%)")
ax2.set_title("Tasa de ataque por protocolo")
ax2.set_ylim(0, 60)
for bar, val in zip(bars, pr_pd["tasa_ataque_pct"]):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f"{val:.1f}%", ha="center", fontsize=9, fontweight="bold")

# Gráfico 3: Tasa de ataque por cifrado
ax3 = axes[0, 2]
ci_pd = df_cifrado.toPandas().sort_values("tasa_ataque_pct", ascending=True)
cols_ci = ["#4CAF50", "#FFC107", "#F44336"]
ax3.barh(ci_pd["encryption_used"], ci_pd["tasa_ataque_pct"],
         color=cols_ci[:len(ci_pd)], edgecolor="white")
ax3.set_xlabel("Tasa de ataque (%)")
ax3.set_title("Tasa de ataque por tipo de cifrado")
for i, (_, row) in enumerate(ci_pd.iterrows()):
    ax3.text(row["tasa_ataque_pct"] + 0.2, i,
             f"{row['tasa_ataque_pct']:.1f}%", va="center", fontsize=9)

# Gráfico 4: Tasa de ataque por navegador
ax4 = axes[1, 0]
br_pd = df_browser.toPandas().sort_values("tasa_ataque_pct", ascending=False)
colors_br = plt.cm.Set2.colors[:len(br_pd)]
ax4.bar(br_pd["browser_type"], br_pd["tasa_ataque_pct"],
        color=colors_br, edgecolor="white")
ax4.set_xlabel("Navegador"); ax4.set_ylabel("Tasa de ataque (%)")
ax4.set_title("Tasa de ataque por navegador")
ax4.tick_params(axis="x", rotation=15)
for i, (_, row) in enumerate(br_pd.iterrows()):
    ax4.text(i, row["tasa_ataque_pct"] + 0.2,
             f"{row['tasa_ataque_pct']:.1f}%", ha="center", fontsize=8)

# Gráfico 5: ip_reputation_score — comparativa ataque vs no ataque
ax5 = axes[1, 1]
df_comp_pd = df.select(
    "ip_reputation_score", "attack_detected"
).toPandas()
no_atk = df_comp_pd[df_comp_pd["attack_detected"] == 0]["ip_reputation_score"]
si_atk = df_comp_pd[df_comp_pd["attack_detected"] == 1]["ip_reputation_score"]
ax5.hist(no_atk, bins=30, alpha=0.6, color="#2196F3", label="Sin ataque", density=True)
ax5.hist(si_atk, bins=30, alpha=0.6, color="#F44336", label="Con ataque",  density=True)
ax5.set_xlabel("IP Reputation Score")
ax5.set_ylabel("Densidad")
ax5.set_title("Distribución IP Reputation Score")
ax5.legend()

# Gráfico 6: failed_logins y login_attempts (boxplot comparativo)
ax6 = axes[1, 2]
data_box = [
    df_comp_pd[df_comp_pd["attack_detected"] == 0]["ip_reputation_score"].values,
    df_comp_pd[df_comp_pd["attack_detected"] == 1]["ip_reputation_score"].values,
]
bp = ax6.boxplot(data_box, patch_artist=True, notch=False,
                 labels=["Sin ataque", "Con ataque"])
for patch, color in zip(bp["boxes"], COLORS_ATK):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
ax6.set_ylabel("IP Reputation Score")
ax6.set_title("Boxplot IP Rep. Score\npor resultado de sesión")

plt.tight_layout()
plt.savefig("resultados_batch_ciberseguridad.png", dpi=150, bbox_inches="tight")
plt.show()
print("\n Gráfica guardada: resultados_batch_ciberseguridad.png")

# ── 8. TABLA RESUMEN FINAL
print("\n" + "="*65)
print("   RESUMEN DEL PROCESAMIENTO BATCH — INTRUSIONES CIBERSEGURIDAD")
print("="*65)
print(f"  Registros totales procesados : {total:,}")
at_row = df_ataques.toPandas()
print(f"  Sesiones SIN ataque          : {int(at_row[at_row.attack_detected==0]['total'])}")
print(f"  Sesiones CON ataque          : {int(at_row[at_row.attack_detected==1]['total'])}")
print(f"  Tasa global de intrusión     : {int(at_row[at_row.attack_detected==1]['total'])/total*100:.1f}%")

spark.stop()
print("\n SparkSession cerrada.")
