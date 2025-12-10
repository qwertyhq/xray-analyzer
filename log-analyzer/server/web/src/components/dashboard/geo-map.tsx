"use client";

import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import Map, { Source, Layer, Popup } from "react-map-gl/mapbox";
import type { MapRef } from "react-map-gl/mapbox";
import type { FeatureCollection, Point } from "geojson";
import type { LayerProps } from "react-map-gl/mapbox";
import type mapboxgl from "mapbox-gl";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Globe, Maximize2, Minimize2, X } from "lucide-react";
import "mapbox-gl/dist/mapbox-gl.css";

// Country centroids for geo positioning
const countryCentroids: Record<string, [number, number]> = {
  "RU": [37.6173, 55.7558],
  "US": [-95.7129, 37.0902],
  "DE": [10.4515, 51.1657],
  "FR": [2.3522, 46.2276],
  "GB": [-0.1276, 51.5074],
  "NL": [5.2913, 52.1326],
  "UA": [30.5234, 50.4501],
  "PL": [19.1451, 51.9194],
  "BY": [27.9534, 53.9045],
  "KZ": [66.9237, 48.0196],
  "TR": [32.8597, 39.9334],
  "IT": [12.5674, 41.8719],
  "ES": [-3.7038, 40.4168],
  "SE": [18.0686, 59.3293],
  "FI": [24.9384, 60.1699],
  "CN": [116.4074, 39.9042],
  "JP": [139.6917, 35.6895],
  "KR": [126.978, 37.5665],
  "BR": [-47.9292, -15.7797],
  "AR": [-58.3816, -34.6037],
  "AU": [149.1300, -35.2809],
  "IN": [77.1025, 28.7041],
  "AE": [55.2708, 25.2048],
  "SG": [103.8198, 1.3521],
  "CA": [-75.6972, 45.4215],
  "MX": [-99.1332, 19.4326],
  "CZ": [14.4378, 50.0755],
  "AT": [16.3738, 48.2082],
  "CH": [8.5417, 47.3769],
  "BE": [4.3517, 50.8503],
  "PT": [-9.1393, 38.7223],
  "NO": [10.7522, 59.9139],
  "DK": [12.5683, 55.6761],
  "IE": [-6.2603, 53.3498],
  "GR": [23.7275, 37.9838],
  "IL": [34.7818, 32.0853],
  "ZA": [28.0473, -26.2041],
  "EG": [31.2357, 30.0444],
  "ID": [106.8456, -6.2088],
  "TH": [100.5018, 13.7563],
  "VN": [105.8342, 21.0285],
  "MY": [101.6869, 3.1390],
  "PH": [120.9842, 14.5995],
  "HK": [114.1694, 22.3193],
  "TW": [121.5654, 25.0330],
  "LT": [25.2797, 54.6872],
  "LV": [24.6032, 56.9496],
  "EE": [24.7536, 59.4370],
  "RO": [26.1025, 44.4268],
  "BG": [23.3219, 42.6977],
  "HU": [19.0402, 47.4979],
  "SK": [17.1077, 48.1486],
  "HR": [15.9819, 45.8150],
  "RS": [20.4651, 44.7866],
  "SI": [14.5058, 46.0569],
  "MD": [28.8638, 47.0105],
  "GE": [44.7833, 41.7151],
  "AM": [44.5035, 40.1792],
  "AZ": [49.8671, 40.4093],
  "UZ": [69.2401, 41.2995],
  "KG": [74.5698, 42.8746],
  "TJ": [68.7738, 38.5598],
};

export interface GeoData {
  country: string;
  country_code: string;
  count: number;
  users: number;
}

export interface CityData {
  city: string;
  country: string;
  country_code: string;
  count: number;
  users: number;
  latitude: number;
  longitude: number;
}

interface GeoMapProps {
  data: GeoData[];
  cityData?: CityData[];
  title?: string;
  mode?: "countries" | "cities";
}

// Country flag emoji from country code
function getFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return "🌍";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;

export function GeoMap({ data, cityData = [], title = "Geographic Distribution", mode = "cities" }: GeoMapProps) {
  const mapRef = useRef<MapRef>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [popupInfo, setPopupInfo] = useState<{
    longitude: number;
    latitude: number;
    country: string;
    country_code: string;
    city?: string;
    count: number;
    users: number;
  } | null>(null);

  // Handle escape key to exit fullscreen
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) {
        setIsFullscreen(false);
      }
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [isFullscreen]);

  // Resize map when fullscreen changes
  useEffect(() => {
    if (mapRef.current) {
      setTimeout(() => {
        mapRef.current?.resize();
      }, 100);
    }
  }, [isFullscreen]);

  // Convert city data to GeoJSON (uses actual coordinates)
  const cityGeojson = useMemo((): FeatureCollection<Point> => {
    return {
      type: "FeatureCollection",
      features: cityData
        .filter(item => item.latitude !== 0 && item.longitude !== 0)
        .map(item => ({
          type: "Feature" as const,
          geometry: {
            type: "Point" as const,
            coordinates: [item.longitude, item.latitude],
          },
          properties: {
            city: item.city,
            country: item.country,
            country_code: item.country_code,
            count: item.count,
            users: item.users,
          },
        })),
    };
  }, [cityData]);

  // Convert country data to GeoJSON (uses country centroids)
  const countryGeojson = useMemo((): FeatureCollection<Point> => {
    return {
      type: "FeatureCollection",
      features: data
        .filter(item => countryCentroids[item.country_code])
        .map(item => {
          const coords = countryCentroids[item.country_code];
          return {
            type: "Feature" as const,
            geometry: {
              type: "Point" as const,
              coordinates: coords,
            },
            properties: {
              country: item.country,
              country_code: item.country_code,
              count: item.count,
              users: item.users,
            },
          };
        }),
    };
  }, [data]);

  // Choose which data to display based on mode
  const geojson = mode === "cities" && cityData.length > 0 ? cityGeojson : countryGeojson;
  const displayData = useMemo(() => 
    mode === "cities" && cityData.length > 0 ? cityData : data,
    [mode, cityData, data]
  );

  const totalCount = useMemo(() => displayData.reduce((sum, d) => sum + d.count, 0), [displayData]);
  const maxCount = useMemo(() => Math.max(...displayData.map(d => d.count), 1), [displayData]);

  // Layer style for circles
  const layerStyle: LayerProps = useMemo(() => ({
    id: "geo-points",
    type: "circle",
    paint: {
      "circle-radius": [
        "interpolate",
        ["linear"],
        ["get", "count"],
        1, 8,
        maxCount * 0.25, 15,
        maxCount * 0.5, 22,
        maxCount, 35,
      ],
      "circle-color": [
        "interpolate",
        ["linear"],
        ["get", "count"],
        1, "rgba(59, 130, 246, 0.6)",
        maxCount * 0.5, "rgba(239, 68, 68, 0.7)",
        maxCount, "rgba(239, 68, 68, 0.9)",
      ],
      "circle-stroke-width": 2,
      "circle-stroke-color": "rgba(255, 255, 255, 0.8)",
    },
  }), [maxCount]);

  const onClick = useCallback((event: mapboxgl.MapLayerMouseEvent) => {
    const feature = event.features?.[0];
    if (feature && feature.geometry.type === "Point") {
      const coords = feature.geometry.coordinates as [number, number];
      setPopupInfo({
        longitude: coords[0],
        latitude: coords[1],
        country: feature.properties?.country || "",
        country_code: feature.properties?.country_code || "",
        city: feature.properties?.city || undefined,
        count: feature.properties?.count || 0,
        users: feature.properties?.users || 0,
      });
    }
  }, []);

  const onMouseEnter = useCallback(() => {
    if (mapRef.current) {
      mapRef.current.getCanvas().style.cursor = "pointer";
    }
  }, []);

  const onMouseLeave = useCallback(() => {
    if (mapRef.current) {
      mapRef.current.getCanvas().style.cursor = "";
    }
  }, []);

  if (!MAPBOX_TOKEN) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-500" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6 text-muted-foreground">
            <Globe className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">Mapbox API key not configured</p>
            <p className="text-xs mt-1">Set NEXT_PUBLIC_MAPBOX_TOKEN in environment</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-500" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-6 text-muted-foreground">
            <Globe className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No geographic data available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      {/* Fullscreen overlay */}
      {isFullscreen && (
        <div className="fixed inset-0 z-50 bg-background">
          <div className="absolute top-4 left-4 z-10 flex items-center gap-4">
            <div className="flex items-center gap-2 bg-background/90 backdrop-blur-sm rounded-lg px-3 py-2">
              <Globe className="h-5 w-5 text-blue-500" />
              <span className="font-medium">{title}</span>
              <span className="text-muted-foreground text-sm">
                {mode === "cities" && cityData.length > 0 
                  ? `${cityData.length} cities • ${totalCount.toLocaleString()} connections`
                  : `${data.length} countries • ${totalCount.toLocaleString()} connections`
                }
              </span>
            </div>
          </div>
          <Button
            variant="outline"
            size="icon"
            className="absolute top-4 right-4 z-10"
            onClick={() => setIsFullscreen(false)}
          >
            <X className="h-4 w-4" />
          </Button>
          <Map
            ref={mapRef}
            mapboxAccessToken={MAPBOX_TOKEN}
            initialViewState={{
              longitude: 40,
              latitude: 40,
              zoom: 2.5,
            }}
            style={{ width: "100%", height: "100%" }}
            mapStyle="mapbox://styles/mapbox/dark-v11"
            interactiveLayerIds={["geo-points"]}
            onClick={onClick}
            onMouseEnter={onMouseEnter}
            onMouseLeave={onMouseLeave}
            attributionControl={false}
          >
            <Source id="geo-data" type="geojson" data={geojson}>
              <Layer {...layerStyle} />
            </Source>

            {popupInfo && (
              <Popup
                longitude={popupInfo.longitude}
                latitude={popupInfo.latitude}
                anchor="bottom"
                onClose={() => setPopupInfo(null)}
                closeButton={true}
                closeOnClick={false}
                className="geo-popup"
              >
                <div className="p-2 min-w-[140px] bg-zinc-900 text-white rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-lg">{getFlag(popupInfo.country_code)}</span>
                    <div className="flex flex-col">
                      {popupInfo.city && (
                        <span className="font-medium text-white">{popupInfo.city}</span>
                      )}
                      <span className={popupInfo.city ? "text-sm text-zinc-400" : "font-medium text-white"}>
                        {popupInfo.country}
                      </span>
                    </div>
                  </div>
                  <div className="text-sm space-y-1">
                    <div className="flex justify-between">
                      <span className="text-zinc-400">Connections:</span>
                      <span className="font-mono text-white">{popupInfo.count.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-400">Users:</span>
                      <span className="font-mono text-white">{popupInfo.users.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-400">Share:</span>
                      <span className="font-mono text-white">
                        {((popupInfo.count / totalCount) * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              </Popup>
            )}
          </Map>

          {/* Legend in fullscreen */}
          <div className="absolute bottom-4 left-4 bg-background/90 backdrop-blur-sm rounded-md p-2 text-xs">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded-full bg-blue-500/60" />
                <span>Low</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                <span>High</span>
              </div>
            </div>
          </div>

          {/* Top locations in fullscreen - sidebar */}
          <div className="absolute bottom-4 right-4 bg-background/90 backdrop-blur-sm rounded-lg p-3 max-w-[250px] max-h-[300px] overflow-y-auto scrollbar-thin">
            <h4 className="text-sm font-medium mb-2">Top Locations</h4>
            <div className="space-y-2">
              {mode === "cities" && cityData.length > 0
                ? cityData.slice(0, 10).map((item, idx) => (
                    <div key={`${item.city}-${item.country_code}-${idx}`} className="flex items-center gap-2 text-sm">
                      <span>{getFlag(item.country_code)}</span>
                      <span className="truncate flex-1">{item.city}</span>
                      <Badge variant="secondary" className="text-xs">
                        {item.count.toLocaleString()}
                      </Badge>
                    </div>
                  ))
                : data.slice(0, 10).map((item) => (
                    <div key={item.country_code} className="flex items-center gap-2 text-sm">
                      <span>{getFlag(item.country_code)}</span>
                      <span className="truncate flex-1">{item.country}</span>
                      <Badge variant="secondary" className="text-xs">
                        {item.count.toLocaleString()}
                      </Badge>
                    </div>
                  ))
              }
            </div>
          </div>
        </div>
      )}

      {/* Normal card view */}
      <Card className="overflow-hidden">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-500" />
              {title}
            </CardTitle>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              onClick={() => setIsFullscreen(true)}
              title="Fullscreen"
            >
              <Maximize2 className="h-3.5 w-3.5" />
            </Button>
          </div>
          <CardDescription className="text-xs">
            {mode === "cities" && cityData.length > 0 
              ? `${cityData.length} cities • ${totalCount.toLocaleString()} connections`
              : `${data.length} countries • ${totalCount.toLocaleString()} connections`
            }
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="h-[300px] relative">
            <Map
              ref={isFullscreen ? undefined : mapRef}
              mapboxAccessToken={MAPBOX_TOKEN}
              initialViewState={{
                longitude: 40,
                latitude: 40,
                zoom: 1.5,
              }}
              style={{ width: "100%", height: "100%" }}
              mapStyle="mapbox://styles/mapbox/dark-v11"
              interactiveLayerIds={["geo-points"]}
              onClick={onClick}
              onMouseEnter={onMouseEnter}
              onMouseLeave={onMouseLeave}
              attributionControl={false}
            >
              <Source id="geo-data" type="geojson" data={geojson}>
                <Layer {...layerStyle} />
              </Source>

              {popupInfo && !isFullscreen && (
                <Popup
                  longitude={popupInfo.longitude}
                  latitude={popupInfo.latitude}
                  anchor="bottom"
                  onClose={() => setPopupInfo(null)}
                  closeButton={true}
                  closeOnClick={false}
                  className="geo-popup"
                >
                  <div className="p-2 min-w-[140px] bg-zinc-900 text-white rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-lg">{getFlag(popupInfo.country_code)}</span>
                      <div className="flex flex-col">
                        {popupInfo.city && (
                          <span className="font-medium text-white">{popupInfo.city}</span>
                        )}
                        <span className={popupInfo.city ? "text-sm text-zinc-400" : "font-medium text-white"}>
                          {popupInfo.country}
                        </span>
                      </div>
                    </div>
                    <div className="text-sm space-y-1">
                      <div className="flex justify-between">
                        <span className="text-zinc-400">Connections:</span>
                        <span className="font-mono text-white">{popupInfo.count.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-400">Users:</span>
                        <span className="font-mono text-white">{popupInfo.users.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-400">Share:</span>
                        <span className="font-mono text-white">
                          {((popupInfo.count / totalCount) * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  </div>
                </Popup>
              )}
            </Map>

            {/* Legend */}
            <div className="absolute bottom-2 left-2 bg-background/90 backdrop-blur-sm rounded-md p-2 text-xs">
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded-full bg-blue-500/60" />
                  <span>Low</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded-full bg-red-500/80" />
                  <span>High</span>
                </div>
              </div>
            </div>
          </div>

          {/* Top locations list */}
          <div className="p-3 border-t max-h-[150px] overflow-y-auto scrollbar-thin">
            <div className="grid grid-cols-2 gap-2">
              {mode === "cities" && cityData.length > 0
                ? cityData.slice(0, 6).map((item, idx) => (
                    <div key={`${item.city}-${item.country_code}-${idx}`} className="flex items-center gap-2 text-sm">
                      <span>{getFlag(item.country_code)}</span>
                      <span className="truncate flex-1">{item.city}</span>
                      <Badge variant="secondary" className="text-xs">
                        {item.count.toLocaleString()}
                      </Badge>
                    </div>
                  ))
                : data.slice(0, 6).map((item) => (
                    <div key={item.country_code} className="flex items-center gap-2 text-sm">
                      <span>{getFlag(item.country_code)}</span>
                      <span className="truncate flex-1">{item.country}</span>
                      <Badge variant="secondary" className="text-xs">
                        {item.count.toLocaleString()}
                      </Badge>
                    </div>
                  ))
              }
            </div>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
