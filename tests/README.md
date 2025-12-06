# VulnSleuth Testing Guide

## Overview

This directory contains the comprehensive test suite for VulnSleuth. The tests cover all major components including the core engine, database operations, plugin system, and various scanning modules.

## Test Structure

bash```
tests/
├── __init__.py              # Test package initialization
├── conftest.py             # Test configuration and utilities  
├── test_engine.py          # Core engine functionality tests
├── test_database.py        # Database operations tests
├── test_plugins.py         # Plugin system tests
└── run_tests.py           # Test runner script
``

## Running Tests

### Run All Tests

```bash
cd tests
python run_tests.py
```

### Run Specific Test Module

```bash
python run_tests.py engine     # Run engine tests
python run_tests.py database   # Run database tests  
python run_tests.py plugins    # Run plugin tests
```

### Run Individual Test Classes

```bash
python -m unittest test_engine.TestScanEngine
python -m unittest test_database.TestDatabaseManager
python -m unittest test_plugins.TestPluginSystem
```

## Test Categories

### Core Engine Tests (`test_engine.py`)

- __TestScanEngine__: Tests for main scanning engine
  - Scan initialization and execution
  - Target processing and validation
  - Plugin management integration
  - Result aggregation
  - Error handling
  - Concurrent scanning

- __TestScanConfiguration__: Tests for configuration management
  - Configuration loading and validation
  - Default value fallbacks
  - Scan option processing

### Database Tests (`test_database.py`)

- __TestDatabaseManager__: Tests for database operations
  - Database initialization and schema creation
  - CRUD operations for scans, targets, vulnerabilities
  - Scan results storage and retrieval
  - CVE data management
  - Data integrity constraints
  - Backup and recovery
  - Performance testing

- __TestDatabaseMigration__: Tests for schema migrations
  - Version tracking
  - Migration detection
  - Schema upgrade processes

### Plugin Tests (`test_plugins.py`)

- __TestPluginSystem__: Tests for plugin architecture
  - Plugin loading and management
  - Metadata validation
  - Execution context handling
  - Error handling in plugins
  - Plugin filtering by category

- __TestBuiltinPlugins__: Tests for built-in plugins
  - Local system checker
  - Network scanner
  - Web application scanner

- __TestPluginDevelopment__: Tests for plugin development utilities
  - Template structure validation
  - Metadata requirements
  - Finding severity validation

## Test Configuration

The `conftest.py` file provides:

### VulnSleuthTestCase Base Class

```python
class VulnSleuthTestCase(unittest.TestCase):
    """Base test case with common utilities"""
    
    def setUp(self):
        # Creates temporary test environment
        # Sets up mock configuration
        # Initializes test database
    
    def create_test_db(self):
        # Creates isolated test database
    
    def create_mock_target(self):
        # Returns mock target for testing
    
    def create_mock_vulnerability(self):
        # Returns mock vulnerability finding
```

### Mock Configuration

```python
mock_config = {
    'database': {
        'path': '/tmp/test_vulnsleuth.db',
        'backup_enabled': False
    },
    'logging': {
        'level': 'DEBUG',
        'file': '/tmp/test.log'
    },
    'scanning': {
        'max_threads': 2,
        'timeout': 5,
        'retry_attempts': 1
    }
}
```

## Writing New Tests

### Test Naming Convention

- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>`
- Test methods: `test_<functionality_description>`

### Example Test Class

```python
class TestNewFeature(VulnSleuthTestCase):
    """Test cases for new feature"""
    
    def setUp(self):
        """Set up test environment"""
        super().setUp()
        # Additional setup for this test class
    
    def test_basic_functionality(self):
        """Test basic feature functionality"""
        # Arrange
        test_data = self.create_test_data()
        
        # Act
        result = feature.process(test_data)
        
        # Assert
        self.assertIsNotNone(result)
        self.assertEqual(result.status, 'success')
    
    def test_error_handling(self):
        """Test feature error handling"""
        with self.assertRaises(ExpectedError):
            feature.process(invalid_data)
```

### Testing Guidelines

1. __Isolation__: Each test should be independent and not rely on other tests
2. __Cleanup__: Always clean up resources in `tearDown()` or use context managers
3. __Mocking__: Use mocks for external dependencies (network, file system, etc.)
4. __Coverage__: Test both success and failure scenarios
5. __Performance__: Include performance tests for critical paths
6. __Documentation__: Document complex test scenarios

### Mock Usage Examples

```python
# Mock external service calls
with patch('requests.get') as mock_get:
    mock_get.return_value.json.return_value = {'status': 'ok'}
    result = service.call_api()

# Mock file operations
with patch('builtins.open', mock_open(read_data='test data')):
    result = file_processor.read_config()

# Mock database operations
with patch('sqlite3.connect') as mock_connect:
    mock_connect.return_value = mock_db
    result = db_manager.query_data()
```

## Test Data Management

### Temporary Files

- Use `tempfile.mkdtemp()` for temporary directories
- Clean up in `tearDown()` method
- Use context managers when possible

### Test Database

- Each test gets isolated SQLite database
- Automatically cleaned up after test completion
- Pre-populated with minimal required data

### Mock Data Generators

```python
def create_mock_scan(self):
    return {
        'name': 'Test Scan',
        'description': 'Test scan for unit testing',
        'scan_type': 'network',
        'status': 'running'
    }

def create_mock_vulnerability(self):
    return VulnerabilityFinding(
        title="Mock Vulnerability",
        description="Test vulnerability",
        severity="medium",
        cvss_score=5.0,
        solution="Test solution"
    )
```

## Continuous Integration

### Test Requirements

- All tests must pass before merging
- Minimum 80% code coverage required
- No skipped tests without justification
- Performance tests within acceptable limits

### CI Configuration

```yaml
# Example CI pipeline
test:
  script:
    - pip install -r requirements.txt
    - pip install -r test-requirements.txt
    - python tests/run_tests.py
  coverage: '/TOTAL.*\s+(\d+%)$/'
```

## Debugging Tests

### Verbose Output

```bash
python -m unittest -v test_module.TestClass.test_method
```

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run specific test with debugging
unittest.main(verbosity=2)
```

### Test Isolation Issues

```bash
# Run tests in random order to catch isolation issues
python -m pytest --random-order tests/
```

## Performance Testing

### Benchmarking

```python
def test_scan_performance(self):
    """Test scan completes within time limit"""
    import time
    
    start_time = time.time()
    results = self.engine.scan_targets(large_target_list)
    end_time = time.time()
    
    # Should complete within reasonable time
    self.assertLess(end_time - start_time, 30.0)
    self.assertGreater(len(results), 0)
```

### Memory Usage

```python
def test_memory_usage(self):
    """Test memory usage stays within limits"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Perform memory-intensive operation
    self.engine.scan_large_dataset()
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable
    self.assertLess(memory_increase, 100 * 1024 * 1024)  # < 100MB
```

## Best Practices

1. __Test First__: Write tests before implementing features when possible
2. __Small Tests__: Keep tests focused on single functionality
3. __Clear Names__: Use descriptive test method names
4. __Arrange-Act-Assert__: Structure tests clearly
5. __Mock External__: Mock all external dependencies
6. __Clean State__: Ensure tests don't affect each other
7. __Error Cases__: Test error conditions thoroughly
8. __Performance__: Include performance regression tests
9. __Documentation__: Document complex test scenarios
10. __Maintenance__: Keep tests updated with code changes
