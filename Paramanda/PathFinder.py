import json, os, glob
import networkx as nx

INPUT_FOLDER = "input"
OUTPUT_FOLDER = "output"

class PathFinder:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.da_group_sid = None

    def load_data(self):
        # Load group memberships → find Domain Admins SID
        groups_data = self._read_json("groups")
        for group in groups_data:
            name = group.get("Properties", {}).get("name", "")
            sid = group.get("ObjectIdentifier")
            if "DOMAIN ADMINS" in name.upper():
                self.da_group_sid = sid
                print(f"[+] Found Domain Admins Group: {name} ({sid})")
            for member in group.get("Members", []):
                m_sid = member.get("ObjectIdentifier") if isinstance(member, dict) else member
                self.graph.add_edge(m_sid, sid, label="MemberOf")

        # Load users + ACL-based edges
        for user in self._read_json("users"):
            u_sid = user.get("ObjectIdentifier")
            u_name = user.get("Properties", {}).get("name", "Unknown")
            self.graph.add_node(u_sid, name=u_name, type="User")
            for ace in user.get("Aces", []):
                target = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if right in ["GenericAll", "GenericWrite", "Owns", "WriteDacl", "WriteOwner"]:
                    self.graph.add_edge(target, u_sid, label=right)

        # Load computers + session-based lateral movement
        for comp in self._read_json("computers"):
            c_sid = comp.get("ObjectIdentifier")
            c_name = comp.get("Properties", {}).get("name", "Unknown")
            self.graph.add_node(c_sid, name=c_name, type="Computer")
            for session in comp.get("Sessions", []):
                user_sid = session.get("UserSID") if isinstance(session, dict) else session
                if user_sid:
                    self.graph.add_edge(c_sid, user_sid, label="HasSession")

    def _read_json(self, file_type):
        pattern = os.path.join(INPUT_FOLDER, f"*{file_type}.json")
        files = glob.glob(pattern)
        if not files:
            return []
        with open(files[0], 'r', encoding='utf-8-sig') as f:
            return json.load(f).get("data", [])

    def analyze_paths(self):
        results = []
        users = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "User"]
        for start_node in users:
            try:
                path = nx.shortest_path(self.graph, source=start_node, target=self.da_group_sid)
                if len(path) > 1:
                    results.append({
                        "source": self.graph.nodes[start_node].get("name", "Unknown"),
                        "hops": len(path) - 1,
                        "attack_story": self.generate_narrative(path)
                    })
            except (nx.NetworkXNoPath, KeyError):
                continue
        return results

    def generate_narrative(self, path):
        story = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            u_name = self.graph.nodes[u].get("name", u)
            v_name = self.graph.nodes[v].get("name", v)
            relation = self.graph.get_edge_data(u, v).get("label", "controls")
            if relation == "MemberOf":
                story.append(f"{u_name} is a member of {v_name}.")
            elif relation == "HasSession":
                story.append(f"An attacker on {u_name} can hijack the session of {v_name}.")
            else:
                story.append(f"{u_name} has {relation} rights over {v_name}.")
        return " ".join(story)

def main():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    engine = PathFinder()
    engine.load_data()
    paths = engine.analyze_paths()
    with open(os.path.join(OUTPUT_FOLDER, "attack_paths.json"), 'w') as f:
        json.dump(paths, f, indent=4)
    print(f"[+] Analysis Complete! {len(paths)} paths found.")

if __name__ == "__main__":
    main()
