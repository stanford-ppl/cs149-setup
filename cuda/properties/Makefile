
all: device_properties

device_properties:
	nvcc -o device_properties -arch=compute_20 device_properties.cu

clean:
	rm -f device_properties *.o
