from django.test import TestCase

from ...common import EllipticCurve


class EllipticCurveTest(TestCase):
    def test_get_all_elliptic_curves(self):
        elliptic_curves = EllipticCurve.get_all_elliptic_curves()
        self.assertTrue(isinstance(elliptic_curves, list))
        for each in elliptic_curves:
            self.assertTrue(isinstance(each, EllipticCurve))

    def test_get_available_elliptic_curves_returns_a_list_of_elliptic_curve_elements(self):
        elliptic_curves = EllipticCurve.get_available_elliptic_curves()

        self.assertTrue(isinstance(elliptic_curves, list))

        for each in elliptic_curves:
            self.assertTrue(isinstance(each, EllipticCurve))

    def test_get_available_elliptic_curves_returns_a_list_of_available_elements(self):
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        elliptic_curves = EllipticCurve.get_available_elliptic_curves()

        for each in elliptic_curves:
            self.assertTrue(backend.elliptic_curve_supported(each))
