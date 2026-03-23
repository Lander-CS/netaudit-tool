from setuptools import setup, find_packages

setup(
    name="netaudit",
    version="1.0.0",
    description="Ferramenta Profissional de Auditoria de Redes",
    packages=find_packages(),
    install_requires=[
        # Adicione dependências aqui se tiver (ex: 'requests')
    ],
    entry_points={
        'console_scripts': [
            'netaudit=src.main:main',
        ],
    },
)