const express = require('express');
const neo4j = require('neo4j-driver');
const cors = require('cors');

// --- Configuration ---
// Replace these with your actual Neo4j credentials
const NEO4J_URI = 'bolt://localhost:7687'; 
const NEO4J_USER = 'neo4j';
const NEO4J_PASSWORD = 'neo4jpass123'; 
const PORT = 3000;

const app = express();
app.use(cors()); // Allow the frontend to make requests to this backend

// Initialize Neo4j Driver
const driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD));

// Helper function to safely parse Neo4j Integers to standard JavaScript Numbers
function parseProperties(properties) {
    if (!properties) return {};
    const parsed = {};
    for (const [key, value] of Object.entries(properties)) {
        if (neo4j.isInt(value)) {
            parsed[key] = value.toNumber();
        } else {
            parsed[key] = value;
        }
    }
    return parsed;
}

// Helper to determine the best display ID based on your specific schema
function getDisplayId(properties, label) {
    return properties.vuln_id || properties.cwe_id || properties.owasp_id || 
           properties.software_key || properties.cluster_id || 
           properties.profile_id || properties.indicator_key || 'Unknown ID';
}

// --- API Endpoint ---
app.get('/api/graph', async (req, res) => {
    const session = driver.session();
    try {
        // Query to fetch up to 300 nodes and their relationships to prevent overloading the browser.
        // You can adjust the LIMIT to pull more or less data.
        const cypherQuery = `
            MATCH (n)
            WITH n LIMIT 300
            OPTIONAL MATCH (n)-[r]->(m)
            RETURN n, r, m
        `;
        
        const result = await session.run(cypherQuery);
        
        const nodesMap = new Map();
        const links = [];

        result.records.forEach(record => {
            const n = record.get('n');
            const r = record.get('r');
            const m = record.get('m');

            // Process Source Node
            if (n && !nodesMap.has(n.elementId)) {
                const props = parseProperties(n.properties);
                nodesMap.set(n.elementId, {
                    id: n.elementId, // Use elementId for robust D3 linking
                    displayId: getDisplayId(props, n.labels[0]),
                    label: n.labels[0] || 'Unknown',
                    properties: props
                });
            }

            // Process Target Node & Relationship
            if (r && m) {
                if (!nodesMap.has(m.elementId)) {
                    const props = parseProperties(m.properties);
                    nodesMap.set(m.elementId, {
                        id: m.elementId,
                        displayId: getDisplayId(props, m.labels[0]),
                        label: m.labels[0] || 'Unknown',
                        properties: props
                    });
                }
                
                links.push({
                    source: n.elementId,
                    target: m.elementId,
                    type: r.type,
                    properties: parseProperties(r.properties)
                });
            }
        });

        // Send payload to frontend
        res.json({
            nodes: Array.from(nodesMap.values()),
            links: links
        });

    } catch (error) {
        console.error("Neo4j Error:", error);
        res.status(500).json({ error: error.message });
    } finally {
        await session.close();
    }
});

app.listen(PORT, () => {
    console.log(`Backend server running at http://localhost:${PORT}`);
    console.log(`Make sure your Neo4j database is running at ${NEO4J_URI}`);
});