#!/usr/bin/env python3
"""
Launch script for the SDN Controller.

Uses os-ken (maintained Ryu fork) as the OpenFlow controller.

Usage:
    ./venv/bin/python run_controller.py
"""

import eventlet
eventlet.monkey_patch()

import sys
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

controller_path = os.path.join(
    project_dir, 'src', 'sdn_controller', 'trust_controller.py'
)


def main():
    print("=" * 60)
    print("  Zero Trust SDN Controller (os-ken)")
    print("=" * 60)
    print("  OpenFlow listen port: 6633")
    print("  State file: data/controller_state.json")
    print("  Commands file: data/controller_commands.json")
    print("=" * 60)

    from os_ken import cfg
    CONF = cfg.CONF
    CONF.ofp_tcp_listen_port = 6633

    from os_ken.base.app_manager import AppManager
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(['src.sdn_controller.trust_controller'])
    contexts = app_mgr.create_contexts()
    
    print("Discovered Apps:", app_mgr.applications_cls)
    
    services = app_mgr.instantiate_apps(**contexts)

    try:
        from os_ken.lib import hub
        hub.joinall(services)
    except KeyboardInterrupt:
        print("\nController stopped.")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
