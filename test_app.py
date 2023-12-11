import unittest
import sys
from colorama import Fore, Style
from flask_testing import TestCase

from app import app

    
class TestProducts(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['SESSION_COOKIE_NAME'] = 'test_cookie'
        return app

    def print_colored_message(self, message, color=Fore.WHITE):
        print(f"{color}{message}{Style.RESET_ALL}")

    def login(self, username, password):
        response = self.client.post('/login', data=dict(
            username=username,
            password=password
        ))
        return response

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.test_request_context('/'):
            self.login("user", "12345678")


    def test_products(self):
        response = self.client.get('/products')
        self.assertEqual(response.status_code, 200)
        self.print_colored_message("Products Test Passed!✅", color=Fore.GREEN)

    def test_product(self):
        response = self.client.get('/product/1')
        self.assertEqual(response.status_code, 200)
        self.print_colored_message("Product Test Passed! ✅", color=Fore.GREEN)

    def test_product_not_found(self):
        response = self.client.get('/product/100')
        if response.status_code == 404:
            self.print_colored_message("Product Not Found Test Passed! ✅", color=Fore.GREEN)

    def test_add_product(self):
        response = self.client.post('/product', data=dict(
             name="Test Product",
            description="Test Description",
            category_id=10,
            quantity=10,
            price=10.15,
        ))
        if response.status_code == 200:
            self.print_colored_message("Add Product Test Passed! ✅", color=Fore.GREEN)
        else:
            self.print_colored_message("Add Product Test Failed! ❌", color=Fore.RED)

    def test_edit_product(self):
        response = self.client.put('/product/35', data=dict(
            name="Test Product",
            description="Test Description",
            category_id=10,
            quantity=5,
            price=10.15,
        ))
        if response.status_code == 200:
            self.print_colored_message("Edit Product Test Passed! ✅", color=Fore.GREEN)
        else:
            self.print_colored_message("Edit Product Test Failed! ❌", color=Fore.RED)

   
if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestProducts)

    runner = unittest.TextTestRunner(stream=sys.stdout, descriptions=True, verbosity=2, failfast=False, buffer=False)

    result = runner.run(suite)





