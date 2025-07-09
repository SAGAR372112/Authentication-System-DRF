# Create your tests here.
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import json

User = get_user_model()

class UserModelTest(TestCase):
    """Test cases for User model"""
    
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123',
        }
    
    def test_create_user(self):
        """Test creating a user"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.username, self.user_data['username'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
    
    def test_create_superuser(self):
        """Test creating a superuser"""
        user = User.objects.create_superuser(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
    
    def test_user_string_representation(self):
        """Test user string representation"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(str(user), self.user_data['email'])
    
    def test_email_unique_constraint(self):
        """Test email uniqueness"""
        User.objects.create_user(**self.user_data)
        with self.assertRaises(Exception):
            User.objects.create_user(**self.user_data)

class UserRegistrationTest(APITestCase):
    """Test cases for user registration"""
    
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.valid_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123',
            'confirm_password': 'testpass123'
        }
    
    def test_user_registration_success(self):
        """Test successful user registration"""
        response = self.client.post(self.register_url, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['user']['email'], self.valid_data['email'])
        self.assertTrue(User.objects.filter(email=self.valid_data['email']).exists())
    
    def test_user_registration_password_mismatch(self):
        """Test registration with password mismatch"""
        data = self.valid_data.copy()
        data['password_confirm'] = 'wrongpassword'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
    
    def test_user_registration_duplicate_email(self):
        """Test registration with duplicate email"""
        User.objects.create_user(**self.valid_data)
        response = self.client.post(self.register_url, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
    
    def test_user_registration_duplicate_username(self):
        """Test registration with duplicate username"""
        User.objects.create_user(**self.valid_data)
        data = self.valid_data.copy()
        data['email'] = 'different@example.com'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
    
    def test_user_registration_invalid_email(self):
        """Test registration with invalid email format"""
        data = self.valid_data.copy()
        data['email'] = 'invalid-email'
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
    
    def test_user_registration_missing_fields(self):
        """Test registration with missing required fields"""
        data = {'email': 'test@example.com'}
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
        self.assertIn('first_name', response.data)
        self.assertIn('last_name', response.data)
        self.assertIn('password', response.data)

class UserLoginTest(APITestCase):
    """Test cases for user login"""
    
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
    
    def test_user_login_success(self):
        """Test successful user login"""
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['user']['email'], self.user_data['email'])
    
    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': self.user_data['email'],
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
    
    def test_user_login_nonexistent_user(self):
        """Test login with nonexistent user"""
        login_data = {
            'email': 'nonexistent@example.com',
            'password': 'somepassword'
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
    
    def test_user_login_inactive_user(self):
        """Test login with inactive user"""
        self.user.is_active = False
        self.user.save()
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
    
    def test_user_login_missing_fields(self):
        """Test login with missing fields"""
        login_data = {'email': self.user_data['email']}
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

class UserLogoutTest(APITestCase):
    """Test cases for user logout"""
    
    def setUp(self):
        self.client = APIClient()
        self.logout_url = reverse('logout')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = self.refresh_token.access_token
    
    def test_user_logout_success(self):
        """Test successful user logout"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        logout_data = {'refresh': str(self.refresh_token)}
        response = self.client.post(self.logout_url, logout_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
    
    def test_user_logout_invalid_token(self):
        """Test logout with invalid refresh token"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        logout_data = {'refresh': 'invalid_token'}
        response = self.client.post(self.logout_url, logout_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
    
    def test_user_logout_missing_token(self):
        """Test logout without refresh token"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.post(self.logout_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class TokenRefreshTest(APITestCase):
    """Test cases for token refresh"""
    
    def setUp(self):
        self.client = APIClient()
        self.refresh_url = reverse('token_refresh')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh_token = RefreshToken.for_user(self.user)
    
    def test_token_refresh_success(self):
        """Test successful token refresh"""
        refresh_data = {'refresh': str(self.refresh_token)}
        response = self.client.post(self.refresh_url, refresh_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
    
    def test_token_refresh_invalid_token(self):
        """Test token refresh with invalid token"""
        refresh_data = {'refresh': 'invalid_token'}
        response = self.client.post(self.refresh_url, refresh_data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class UserProfileTest(APITestCase):
    """Test cases for user profile"""
    
    def setUp(self):
        self.client = APIClient()
        self.profile_url = reverse('profile')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = self.refresh_token.access_token
    
    def test_get_user_profile_success(self):
        """Test getting user profile"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertEqual(response.data['username'], self.user_data['username'])
    
    def test_get_user_profile_unauthorized(self):
        """Test getting user profile without authentication"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_update_user_profile_success(self):
        """Test updating user profile"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        response = self.client.put(self.profile_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        
        # Verify database was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
    
    def test_partial_update_user_profile(self):
        """Test partial update of user profile"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        update_data = {'first_name': 'PartialUpdate'}
        response = self.client.put(self.profile_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'PartialUpdate')
        self.assertEqual(response.data['last_name'], self.user_data['last_name'])

class ChangePasswordTest(APITestCase):
    """Test cases for changing password"""
    
    def setUp(self):
        self.client = APIClient()
        self.change_password_url = reverse('change_password')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = self.refresh_token.access_token
    
    def test_change_password_success(self):
        """Test successful password change"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        change_data = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123'
        }
        response = self.client.post(self.change_password_url, change_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        
        # Verify password was actually changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpass123'))
        self.assertFalse(self.user.check_password('testpass123'))
    
    def test_change_password_wrong_old_password(self):
        """Test password change with wrong old password"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        change_data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123'
        }
        response = self.client.post(self.change_password_url, change_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
    
    def test_change_password_mismatch(self):
        """Test password change with mismatched new passwords"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        change_data = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
            'confirm_password': 'differentpass123'
        }
        response = self.client.post(self.change_password_url, change_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
    
    def test_change_password_unauthorized(self):
        """Test password change without authentication"""
        change_data = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123'
        }
        response = self.client.post(self.change_password_url, change_data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class ProtectedRouteTest(APITestCase):
    """Test cases for protected routes"""
    
    def setUp(self):
        self.client = APIClient()
        self.protected_url = reverse('protected')
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = self.refresh_token.access_token
    
    def test_protected_route_success(self):
        """Test accessing protected route with valid token"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user'], self.user.email)
    
    def test_protected_route_unauthorized(self):
        """Test accessing protected route without token"""
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_protected_route_invalid_token(self):
        """Test accessing protected route with invalid token"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class JWTTokenTest(APITestCase):
    """Test cases for JWT token functionality"""
    
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)
    
    def test_generate_jwt_tokens(self):
        """Test JWT token generation"""
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token
        
        self.assertIsInstance(refresh, RefreshToken)
        self.assertIsNotNone(str(refresh))
        self.assertIsNotNone(str(access))
    
    def test_jwt_token_payload(self):
        """Test JWT token payload contains correct user info"""
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token
        
        # Check if token contains user_id
        self.assertEqual(access['user_id'], self.user.id)
        self.assertEqual(refresh['user_id'], self.user.id)