import random
from pathlib import Path

# Set up bulletproof paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = PROJECT_ROOT / 'data' / 'generated_50k_config.conf'

def generate_massive_config(num_rules=50000):
    print(f"Generating {num_rules} completely randomized firewall rules...")
    
    # Ensure the data directory exists
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    with OUTPUT_PATH.open('w', encoding='utf-8') as f:
        f.write("config firewall policy\n")
        
        for i in range(1, num_rules + 1):
            f.write(f"    edit {i}\n")
            
            # Roll the dice to decide what kind of rule to build
            chance = random.random()
            
            if chance < 0.0001:  
                # 0.01% chance: Plant an Overly Permissive Rule (ANY to ANY)
                f.write(f'        set name "CRITICAL-FLAW-{i}"\n')
                f.write('        set srcintf "any"\n')
                f.write('        set dstintf "any"\n')
                f.write('        set srcaddr "all"\n')
                f.write('        set dstaddr "all"\n')
                f.write('        set action accept\n')
                f.write('        set schedule "always"\n')
                f.write('        set service "ALL"\n')
                f.write('        set logtraffic disable\n')
                
            elif chance < 0.005: 
                # 0.5% chance: Plant a Logging Disabled blind spot
                f.write(f'        set name "BLIND-SPOT-{i}"\n')
                f.write(f'        set srcintf "port{random.randint(1, 4)}"\n')
                f.write(f'        set dstintf "port{random.randint(1, 4)}"\n')
                f.write(f'        set srcaddr "Subnet_{random.randint(1, 50)}"\n')
                f.write(f'        set dstaddr "Server_{random.randint(1, 50)}"\n')
                f.write('        set action accept\n')
                f.write('        set schedule "always"\n')
                f.write('        set service "HTTPS"\n')
                f.write('        set logtraffic disable\n')
                
            else:
                # Generate a normal, secure rule
                action = random.choice(['accept', 'deny'])
                log = 'all' if action == 'accept' else 'disable'
                
                f.write(f'        set name "Standard-Rule-{i}"\n')
                f.write(f'        set srcintf "port{random.randint(1, 4)}"\n')
                f.write(f'        set dstintf "port{random.randint(1, 4)}"\n')
                f.write(f'        set srcaddr "Subnet_{random.randint(1, 50)}"\n')
                f.write(f'        set dstaddr "Server_{random.randint(1, 50)}"\n')
                f.write(f'        set action {action}\n')
                f.write('        set schedule "always"\n')
                f.write('        set service "HTTPS"\n')
                f.write(f'        set logtraffic {log}\n')
                
            f.write("    next\n")
            
        f.write("end\n")
        
    print(f"✅ Successfully generated {num_rules} randomized rules at:\n{OUTPUT_PATH}")

if __name__ == '__main__':
    generate_massive_config()