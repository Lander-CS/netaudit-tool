import unittest
from analyzer import get_overall_risk, analyze_results
from models import AuditLog

class TestNetworkAudit(unittest.TestCase):
    
    def test_risk_calculation_logic(self):
        """Testa se a calculadora de risco retorna as strings corretas."""
        self.assertEqual(get_overall_risk(50), "CRÍTICO")
        self.assertEqual(get_overall_risk(20), "ALTO")
        self.assertEqual(get_overall_risk(10), "MÉDIO")
        self.assertEqual(get_overall_risk(0), "BAIXO")

    def test_analyzer_report_generation(self):
        """Testa se o relatório agrupa corretamente os dados."""
        mock_data = [
            AuditLog(
                timestamp="2023-01-01", 
                host="192.168.1.50", 
                port=22, 
                status="OPEN", 
                service="SSH", 
                risk_level="MÉDIO", 
                details="Test"
            )
        ]
        
        report = analyze_results(mock_data)
        
        self.assertIn("audit_summary", report)
        self.assertEqual(report["audit_summary"]["total_hosts"], 1)
        self.assertEqual(report["audit_summary"]["medium_risks"], 1)
        
    def test_empty_results(self):
        """Testa comportamento com lista vazia."""
        report = analyze_results([])
        self.assertIn("error", report)

if __name__ == '__main__':
    unittest.main()