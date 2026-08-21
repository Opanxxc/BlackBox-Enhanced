package top.niunaijun.blackbox.core.system.location;

import android.location.GpsSatellite;
import android.location.GpsStatus;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.entity.location.BLocation;
import top.niunaijun.blackbox.utils.Slog;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Enhanced fake location service with GPS simulation, route following, and speed control.
 * Provides realistic GPS behavior including satellite simulation and movement patterns.
 */
public class EnhancedLocationService implements ISystemService {
    public static final String TAG = "EnhancedLocationService";
    
    private static final EnhancedLocationService sService = new EnhancedLocationService();
    private final Executor mThreadPool = Executors.newCachedThreadPool();
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final Map<String, LocationConfig> mLocationConfigs = new HashMap<>();
    private final Map<String, LocationSimulation> mSimulations = new HashMap<>();
    
    public static EnhancedLocationService get() {
        return sService;
    }
    
    /**
     * Configuration for fake location
     */
    public static class LocationConfig {
        public double latitude;
        public double longitude;
        public float accuracy;
        public float altitude;
        public float bearing;
        public float speed;
        public long time;
        public String provider;
        public boolean simulateMovement;
        public float movementSpeed; // meters per second
        public float movementBearing; // degrees
        public boolean simulateSatellites;
        public int satelliteCount;
        public float satelliteSignal; // 0-100
        
        public LocationConfig() {
            this.accuracy = 10.0f;
            this.altitude = 0.0f;
            this.bearing = 0.0f;
            this.speed = 0.0f;
            this.time = System.currentTimeMillis();
            this.provider = LocationManager.GPS_PROVIDER;
            this.simulateMovement = false;
            this.movementSpeed = 0.0f;
            this.movementBearing = 0.0f;
            this.simulateSatellites = true;
            this.satelliteCount = 12;
            this.satelliteSignal = 80.0f;
        }
        
        public Location toLocation() {
            Location location = new Location(provider);
            location.setLatitude(latitude);
            location.setLongitude(longitude);
            location.setAccuracy(accuracy);
            location.setAltitude(altitude);
            location.setBearing(bearing);
            location.setSpeed(speed);
            location.setTime(time);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                location.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos());
            }
            return location;
        }
    }
    
    /**
     * Location simulation state
     */
    public static class LocationSimulation {
        public String packageName;
        public LocationConfig config;
        public boolean isRunning;
        public long lastUpdateTime;
        public double currentLatitude;
        public double currentLongitude;
        public float currentBearing;
        
        public LocationSimulation(String packageName, LocationConfig config) {
            this.packageName = packageName;
            this.config = config;
            this.isRunning = false;
            this.lastUpdateTime = System.currentTimeMillis();
            this.currentLatitude = config.latitude;
            this.currentLongitude = config.longitude;
            this.currentBearing = config.movementBearing;
        }
    }
    
    /**
     * Set fake location for a package
     * @param packageName Package name
     * @param latitude Latitude
     * @param longitude Longitude
     * @param accuracy Accuracy in meters
     */
    public void setFakeLocation(String packageName, double latitude, double longitude, float accuracy) {
        LocationConfig config = new LocationConfig();
        config.latitude = latitude;
        config.longitude = longitude;
        config.accuracy = accuracy;
        config.time = System.currentTimeMillis();
        
        mLocationConfigs.put(packageName, config);
        Slog.d(TAG, "Set fake location for " + packageName + ": " + latitude + ", " + longitude);
    }
    
    /**
     * Set fake location with all parameters
     * @param packageName Package name
     * @param config Location configuration
     */
    public void setFakeLocation(String packageName, LocationConfig config) {
        mLocationConfigs.put(packageName, config);
        Slog.d(TAG, "Set fake location for " + packageName + ": " + config.latitude + ", " + config.longitude);
    }
    
    /**
     * Get fake location for a package
     * @param packageName Package name
     * @return Location configuration or null if not set
     */
    public LocationConfig getFakeLocation(String packageName) {
        return mLocationConfigs.get(packageName);
    }
    
    /**
     * Remove fake location for a package
     * @param packageName Package name
     */
    public void removeFakeLocation(String packageName) {
        mLocationConfigs.remove(packageName);
        stopSimulation(packageName);
        Slog.d(TAG, "Removed fake location for " + packageName);
    }
    
    /**
     * Start location simulation with movement
     * @param packageName Package name
     * @param latitude Starting latitude
     * @param longitude Starting longitude
     * @param speed Movement speed in meters per second
     * @param bearing Initial bearing in degrees
     */
    public void startSimulation(String packageName, double latitude, double longitude, 
                              float speed, float bearing) {
        LocationConfig config = new LocationConfig();
        config.latitude = latitude;
        config.longitude = longitude;
        config.speed = speed;
        config.bearing = bearing;
        config.simulateMovement = true;
        config.movementSpeed = speed;
        config.movementBearing = bearing;
        
        LocationSimulation simulation = new LocationSimulation(packageName, config);
        mSimulations.put(packageName, simulation);
        simulation.isRunning = true;
        
        // Start simulation loop
        mThreadPool.execute(() -> {
            while (simulation.isRunning) {
                updateSimulation(simulation);
                try {
                    Thread.sleep(1000); // Update every second
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        
        Slog.d(TAG, "Started location simulation for " + packageName);
    }
    
    /**
     * Stop location simulation
     * @param packageName Package name
     */
    public void stopSimulation(String packageName) {
        LocationSimulation simulation = mSimulations.get(packageName);
        if (simulation != null) {
            simulation.isRunning = false;
            mSimulations.remove(packageName);
            Slog.d(TAG, "Stopped location simulation for " + packageName);
        }
    }
    
    /**
     * Update simulation position
     * @param simulation Simulation to update
     */
    private void updateSimulation(LocationSimulation simulation) {
        if (!simulation.isRunning) {
            return;
        }
        
        long currentTime = System.currentTimeMillis();
        long deltaTime = currentTime - simulation.lastUpdateTime;
        
        if (deltaTime <= 0) {
            return;
        }
        
        // Calculate new position based on speed and bearing
        double distance = simulation.config.movementSpeed * (deltaTime / 1000.0);
        double bearingRad = Math.toRadians(simulation.currentBearing);
        
        // Calculate new latitude
        double newLatitude = simulation.currentLatitude + 
            (distance * Math.cos(bearingRad)) / 111320.0;
        
        // Calculate new longitude
        double newLongitude = simulation.currentLongitude + 
            (distance * Math.sin(bearingRad)) / (111320.0 * Math.cos(Math.toRadians(simulation.currentLatitude)));
        
        // Add some random variation for realism
        Random random = new Random();
        newLatitude += (random.nextGaussian() * 0.00001);
        newLongitude += (random.nextGaussian() * 0.00001);
        
        // Update simulation state
        simulation.currentLatitude = newLatitude;
        simulation.currentLongitude = newLongitude;
        simulation.lastUpdateTime = currentTime;
        
        // Update config
        simulation.config.latitude = newLatitude;
        simulation.config.longitude = newLongitude;
        simulation.config.time = currentTime;
        simulation.config.speed = simulation.config.movementSpeed;
        simulation.config.bearing = simulation.currentBearing;
        
        // Add slight bearing variation
        simulation.currentBearing += (random.nextGaussian() * 2.0);
        if (simulation.currentBearing < 0) simulation.currentBearing += 360;
        if (simulation.currentBearing >= 360) simulation.currentBearing -= 360;
        
        Slog.d(TAG, "Updated simulation for " + simulation.packageName + 
            ": " + newLatitude + ", " + newLongitude);
    }
    
    /**
     * Follow a route
     * @param packageName Package name
     * @param route List of locations to follow
     * @param speed Speed in meters per second
     * @param callback Callback for route progress
     */
    public void followRoute(String packageName, List<LocationConfig> route, float speed, 
                          IRouteCallback callback) {
        if (route == null || route.isEmpty()) {
            Slog.e(TAG, "Route is empty");
            return;
        }
        
        mThreadPool.execute(() -> {
            try {
                for (int i = 0; i < route.size(); i++) {
                    LocationConfig point = route.get(i);
                    setFakeLocation(packageName, point.latitude, point.longitude, point.accuracy);
                    
                    if (callback != null) {
                        callback.onRouteProgress(packageName, i, route.size());
                    }
                    
                    // Calculate time to next point
                    if (i < route.size() - 1) {
                        LocationConfig nextPoint = route.get(i + 1);
                        double distance = calculateDistance(point.latitude, point.longitude,
                            nextPoint.latitude, nextPoint.longitude);
                        long travelTime = (long) ((distance / speed) * 1000);
                        
                        // Move gradually between points
                        int steps = (int) (travelTime / 1000);
                        for (int step = 0; step < steps; step++) {
                            double progress = (double) step / steps;
                            double lat = point.latitude + (nextPoint.latitude - point.latitude) * progress;
                            double lon = point.longitude + (nextPoint.longitude - point.longitude) * progress;
                            
                            setFakeLocation(packageName, lat, lon, point.accuracy);
                            Thread.sleep(1000);
                        }
                    }
                }
                
                if (callback != null) {
                    callback.onRouteCompleted(packageName);
                }
            } catch (InterruptedException e) {
                Slog.e(TAG, "Route following interrupted");
            }
        });
    }
    
    /**
     * Calculate distance between two points
     * @param lat1 Latitude 1
     * @param lon1 Longitude 1
     * @param lat2 Latitude 2
     * @param lon2 Longitude 2
     * @return Distance in meters
     */
    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        double R = 6371000; // Earth's radius in meters
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                   Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                   Math.sin(dLon / 2) * Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
    
    /**
     * Get simulated GPS status
     * @param packageName Package name
     * @return Simulated GPS status
     */
    public int getSimulatedSatelliteCount(String packageName) {
        LocationConfig config = mLocationConfigs.get(packageName);
        if (config == null || !config.simulateSatellites) {
            return 0;
        }
        return config.satelliteCount;
    }
    
    public float getSimulatedSatelliteSignal(String packageName) {
        LocationConfig config = mLocationConfigs.get(packageName);
        if (config == null || !config.simulateSatellites) {
            return 0.0f;
        }
        return config.satelliteSignal;
    }
    
    /**
     * Generate random location near a point
     * @param centerLat Center latitude
     * @param centerLon Center longitude
     * @param radiusMeters Radius in meters
     * @return Random location within radius
     */
    public LocationConfig generateRandomLocation(double centerLat, double centerLon, double radiusMeters) {
        Random random = new Random();
        
        // Convert radius from meters to degrees
        double radiusLat = radiusMeters / 111320.0;
        double radiusLon = radiusMeters / (111320.0 * Math.cos(Math.toRadians(centerLat)));
        
        // Generate random point within circle
        double angle = random.nextDouble() * 2 * Math.PI;
        double distance = Math.sqrt(random.nextDouble()) * radiusMeters;
        
        double newLat = centerLat + (distance * Math.cos(angle)) / 111320.0;
        double newLon = centerLon + (distance * Math.sin(angle)) / (111320.0 * Math.cos(Math.toRadians(centerLat)));
        
        LocationConfig config = new LocationConfig();
        config.latitude = newLat;
        config.longitude = newLon;
        config.accuracy = (float) (5.0 + random.nextDouble() * 20.0);
        
        return config;
    }
    
    /**
     * Get all active simulations
     * @return Map of package names to simulations
     */
    public Map<String, LocationSimulation> getActiveSimulations() {
        return new HashMap<>(mSimulations);
    }
    
    /**
     * Check if simulation is running for a package
     * @param packageName Package name
     * @return true if simulation is running
     */
    public boolean isSimulating(String packageName) {
        LocationSimulation simulation = mSimulations.get(packageName);
        return simulation != null && simulation.isRunning;
    }
    
    @Override
    public void systemReady() {
        Slog.d(TAG, "EnhancedLocationService initialized");
    }
    
    /**
     * Callback interface for route following
     */
    public interface IRouteCallback {
        void onRouteProgress(String packageName, int currentStep, int totalSteps);
        void onRouteCompleted(String packageName);
        void onRouteError(String packageName, String error);
    }
}
