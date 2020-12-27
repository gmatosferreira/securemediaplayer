from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

SAVETO = 'parameters'

# Generate parameters
print("Generating parameters...")
parameters = dh.generate_parameters(generator=2, key_size=2048)


bytes = parameters.parameter_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.ParameterFormat.PKCS3
)
print()
print(bytes.decode('utf-8'))

# Save them to file
with open(SAVETO, 'wb') as f:
    f.write(bytes)

# Output feedback
print(f"Saved parameters to ./{SAVETO}.")