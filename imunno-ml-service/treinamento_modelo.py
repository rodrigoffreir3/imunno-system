# Arquivo: imunno-ml-service/treinamento_modelo.py
# Conversão do notebook para script treinável

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Gerando dataset fictício para demonstração
data = pd.DataFrame({
    'threat_score': [10, 50, 90, 70, 20, 15, 80, 100],
    'file_size': [200, 300, 150, 400, 250, 260, 270, 100],
    'file_path': [
        'index.php', 'script.js', 'admin.php', 'main.js',
        'upload.php', 'test.php', 'config.js', 'login.php'
    ]
})

# Feature engineering
data['is_php'] = data['file_path'].str.endswith('.php').astype(int)
data['is_js'] = data['file_path'].str.endswith('.js').astype(int)
X = data[['threat_score', 'file_size', 'is_php', 'is_js']]

# Treinamento
model = IsolationForest(contamination='auto', random_state=42)
model.fit(X)

# Salvando
joblib.dump(model, 'imunno_model.joblib')

# Visualização (opcional para análise)
sns.pairplot(X)
plt.suptitle("Distribuição de Features")
plt.show()
