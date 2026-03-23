from setuptools import setup, find_packages

setup(
    name="risksightbr",
    version="1.0.0",
    description="RiskSightBR - Ferramenta de Análise de Riscos e Auditoria de Redes",
    packages=find_packages(),
    install_requires=[
        # Adicione dependências aqui se tiver (ex: 'requests')
    ],
    entry_points={
        'console_scripts': [
            'risksightbr=src.main:main',
        ],
    },
)