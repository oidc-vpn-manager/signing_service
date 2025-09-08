"""
Test to cover exception handling in CRL Generator initialization (lines 97-100).
"""

import pytest
from unittest.mock import patch
from app.utils.crl_generator import CRLGenerator


class TestCRLGeneratorInitException:
    """Test CRL Generator initialization exception handling."""
    
    def test_init_exception_handling(self):
        """Test exception handling in CRL generator initialization - lines 97-100."""
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load_config:
            # Mock to raise exception on first call (CA cert loading)
            mock_load_config.side_effect = Exception("Config loading failed")
            
            # Should not raise exception and should create generator
            generator = CRLGenerator()
            
            # Generator should be created but without CA materials
            assert generator._ca_certificate is None
            assert generator._ca_private_key is None
            
            # Exception should have been caught and generator created successfully
            assert isinstance(generator, CRLGenerator)